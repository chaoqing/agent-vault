// Package egress turns operator-configured upstream proxy profiles into the
// transports and tunnel dialers the MITM ingress uses to reach the *real*
// upstream after credentials have been injected.
//
// The package occupies a narrow slice of the request path: it never inspects
// credentials (brokercore owns injection) and never decides which profile
// applies to a request (that is the UpstreamProxyResolver's job). It only
// answers "given this profile, how do I open a socket to the upstream?"
//
// Supported schemes:
//
//	http, https  — HTTP CONNECT proxy (net/http native tunnelling for HTTPS
//	               upstreams, absolute-form forwarding for plain HTTP ones).
//	socks5       — SOCKS5 with local DNS resolution.
//	socks5h      — SOCKS5 with remote DNS resolution by the proxy.
//
// Network policy: target addresses are still vetted with the same
// private-range/IMDS rules that direct connections use (see
// netguard.ValidateTargetName), even though the connection itself is made by
// the proxy. Without that check, attaching an upstream proxy would silently
// disable SSRF protection. The proxy's own address is exempt — it is an
// explicit operator trust decision, not an attacker-controlled target.
package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/netguard"
	"golang.org/x/net/proxy"
)

// proxyDialTimeout bounds the TCP connect to the proxy itself. Proxy hops are
// usually on the same network (or same host), so anything slower than this
// is a failure worth reporting early rather than a slow link to tolerate.
const proxyDialTimeout = 10 * time.Second

// ErrProxyUnreachable marks failures that came from reaching the proxy itself
// rather than from the upstream behind it. Only these failures may be absorbed
// by the fail_open policy: it is a promise about proxy availability, not a
// licence to route around a proxy that answered fine but disliked the
// request. Callers test with errors.Is, which survives net/http's wrapping.
var ErrProxyUnreachable = errors.New("egress: upstream proxy unreachable")

// Validate checks a resolved profile before it is turned into a transport.
// It mirrors the checks applied when the profile is stored, because storage
// predates resolution and neither side should trust the other.
func Validate(p *brokercore.UpstreamProxy) error {
	if p == nil {
		return fmt.Errorf("egress: nil upstream proxy profile")
	}
	if !brokercore.IsValidUpstreamProxyScheme(p.Scheme) {
		return fmt.Errorf("egress: unsupported upstream proxy scheme %q", p.Scheme)
	}
	if !brokercore.IsValidUpstreamProxyFailure(p.OnFailure) {
		return fmt.Errorf("egress: unsupported failure policy %q", p.OnFailure)
	}
	if err := ValidateHost(p.Host); err != nil {
		return err
	}
	return nil
}

// ValidateHost rejects a proxy endpoint that is not host:port, reusing the
// same character restrictions brokercore applies to upstream hosts so a URL
// cannot smuggle userinfo, a path, or a scheme into the dial address.
func ValidateHost(host string) error {
	if host == "" {
		return fmt.Errorf("egress: upstream proxy host is required")
	}
	if _, port, err := net.SplitHostPort(host); err != nil {
		return fmt.Errorf("egress: upstream proxy host %q must include a port: %w", host, err)
	} else if port == "" {
		return fmt.Errorf("egress: upstream proxy host %q must include a port", host)
	}
	name, port, _ := net.SplitHostPort(host)
	if !brokercore.IsValidHost(name) {
		return fmt.Errorf("egress: invalid upstream proxy host %q", host)
	}
	// SplitHostPort happily accepts "host:80/path"; catch it here rather
	// than reporting an opaque dial failure later.
	if port == "" {
		return fmt.Errorf("egress: upstream proxy host %q must include a port", host)
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return fmt.Errorf("egress: upstream proxy port %q is not a number", port)
		}
	}
	return nil
}

// Bypass reports whether target must skip the proxy, following NO_PROXY
// matching rules: exact host match, suffix match behind an optional leading
// dot, optional port qualification, and "*" to bypass everything. An empty
// list bypasses nothing.
func Bypass(noProxy, target string) bool {
	noProxy = strings.TrimSpace(noProxy)
	if noProxy == "" || target == "" {
		return false
	}
	// Compare without the port; entries may carry their own.
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	for _, entry := range strings.Split(noProxy, ",") {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry == "" {
			continue
		}
		if entry == "*" {
			return true
		}
		// An entry carrying a port only matches the same port.
		if eHost, ePort, err := net.SplitHostPort(entry); err == nil {
			tPort := ""
			if _, p, perr := net.SplitHostPort(target); perr == nil {
				tPort = p
			}
			if ePort != tPort {
				continue
			}
			entry = eHost
		}
		if entry == host {
			return true
		}
		if strings.HasPrefix(entry, ".") && strings.HasSuffix(host, entry) {
			return true
		}
		if strings.HasPrefix(entry, "*.") && strings.HasSuffix(host, entry[1:]) {
			return true
		}
	}
	return false
}

// TunnelDialer opens a raw tunneled connection to addr. It is the WebSocket
// counterpart of the HTTP transport: where RoundTrip can rely on net/http's
// own CONNECT handling, hijacked upgrades need the bare net.Conn.
type TunnelDialer func(ctx context.Context, network, addr string) (net.Conn, error)

// TransportFactory returns a fresh, already-tuned upstream transport. The
// MITM proxy supplies one matching its direct-connection defaults so every
// dial (proxied or not) shares identical timeouts, TLS floors, and pool
// sizing. Returned transports are owned by the Registry after construction.
type TransportFactory func() *http.Transport

// Registry caches transports and tunnel dialers per resolved profile so the
// hot path performs no allocation, no crypto, and no config parsing. Keys are
// profile fingerprints: editing a profile produces a new key, which makes
// changes take effect immediately without restarting the server.
type Registry struct {
	base     TransportFactory
	logger   *slog.Logger
	validate bool // apply netguard target policy before handing off

	mu         sync.RWMutex
	transports map[string]*http.Transport
	tunnels    map[string]TunnelDialer
}

// NewRegistry wraps factory-built transports configured by profile. When
// validate is true every target host is checked against network policy
// before being handed to a proxy. Logger may be non-nil to surface warnings.
func NewRegistry(factory TransportFactory, logger *slog.Logger, validate bool) *Registry {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Registry{
		base:       factory,
		logger:     logger,
		validate:   validate,
		transports: make(map[string]*http.Transport),
		tunnels:    make(map[string]TunnelDialer),
	}
}

// Transport returns the transport to use for requests carried by profile p.
// Results are cached; the returned value must not be mutated by callers.
func (r *Registry) Transport(p *brokercore.UpstreamProxy) (*http.Transport, error) {
	if p == nil {
		return nil, fmt.Errorf("egress: nil profile")
	}
	if err := Validate(p); err != nil {
		return nil, err
	}
	key := p.Fingerprint()

	r.mu.RLock()
	cached := r.transports[key]
	r.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if cached := r.transports[key]; cached != nil {
		return cached, nil
	}
	tr, err := r.buildTransport(p)
	if err != nil {
		return nil, err
	}
	r.transports[key] = tr
	return tr, nil
}

// Tunnel returns a dialer that establishes a tunneled TCP connection to the
// upstream through profile p, used by hijacked WebSocket upgrades.
func (r *Registry) Tunnel(p *brokercore.UpstreamProxy) (TunnelDialer, error) {
	if p == nil {
		return nil, fmt.Errorf("egress: nil profile")
	}
	if err := Validate(p); err != nil {
		return nil, err
	}
	key := p.Fingerprint()

	r.mu.RLock()
	cached := r.tunnels[key]
	r.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if cached := r.tunnels[key]; cached != nil {
		return cached, nil
	}
	dialer, err := r.buildTunnel(p)
	if err != nil {
		return nil, err
	}
	r.tunnels[key] = dialer
	return dialer, nil
}

// CloseIdleConnections drops pooled connections for every cached transport.
func (r *Registry) CloseIdleConnections() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, tr := range r.transports {
		tr.CloseIdleConnections()
	}
}

func (r *Registry) buildTransport(p *brokercore.UpstreamProxy) (*http.Transport, error) {
	tr := r.base()
	if tr == nil {
		return nil, fmt.Errorf("egress: transport factory returned nil")
	}

	switch p.Scheme {
	case brokercore.UpstreamProxySchemeHTTP, brokercore.UpstreamProxySchemeHTTPS:
		proxyURL := &url.URL{Scheme: p.Scheme, Host: p.Host}
		if p.HasAuth() {
			proxyURL.User = url.UserPassword(p.Username, p.Password)
		}
		r.applyHTTPProxy(tr, p, proxyURL)
	case brokercore.UpstreamProxySchemeSOCKS5, brokercore.UpstreamProxySchemeSOCKS5H:
		dialer, err := r.socksDialer(p)
		if err != nil {
			return nil, err
		}
		// SOCKS dialling is expressed through the dial hook, so the proxy
		// field must stay clear — otherwise net/http would try to CONNECT
		// through a proxy that is already speaking SOCKS.
		tr.Proxy = nil
		tr.DialContext = r.wrapTargetPolicy(p, dialer)
		tr.DialTLSContext = nil
	default:
		return nil, fmt.Errorf("egress: unsupported upstream proxy scheme %q", p.Scheme)
	}
	return tr, nil
}

// applyHTTPProxy wires a CONNECT-capable HTTP proxy into tr. The Proxy hook
// is where target validation happens: net/http evaluates it immediately
// before each dial, which keeps the check as close to the connection as it
// is on the direct path.
func (r *Registry) applyHTTPProxy(tr *http.Transport, p *brokercore.UpstreamProxy, proxyURL *url.URL) {
	tr.Proxy = func(req *http.Request) (*url.URL, error) {
		target := req.URL.Host
		if Bypass(p.NoProxy, target) {
			r.logger.Debug("bypassing upstream proxy for no_proxy host",
				slog.String("host", target),
				slog.String("profile", p.Name))
			return nil, nil
		}
		if r.validate {
			if err := netguard.ValidateTargetAddr(req.Context(), target); err != nil {
				return nil, err
			}
		}
		return proxyURL, nil
	}
	// Credentials belong to the proxy hop only. net/http emits this header
	// on CONNECT and never forwards it to the upstream.
	if p.HasAuth() {
		auth := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		tr.ProxyConnectHeader = http.Header{
			"Proxy-Authorization": []string{"Basic " + auth},
		}
	}
	tr.DialContext = r.proxyOrDirect(p)
	// net/http handshakes to an https proxy through DialTLSContext and keeps
	// verifying the *target* with TLSClientConfig, so installing this hook
	// lets the proxy trust anchor stay separate from the upstream's.
	tr.DialTLSContext = r.tlsDial(p, tr.TLSClientConfig)
}

// proxyTCP returns a hook that opens a plain TCP connection to the proxy
// itself. The proxy address is deliberately not vetted against target
// policy: egress proxies routinely live on private addresses, and the
// operator naming one in the config IS the authorization for reaching it.
func (r *Registry) proxyTCP(p *brokercore.UpstreamProxy) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: proxyDialTimeout, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, p.Host)
		if err != nil {
			return nil, fmt.Errorf("%w: profile %q (%s): %w", ErrProxyUnreachable, p.Name, p.Host, err)
		}
		return conn, nil
	}
}

// dialProxyHop is proxyTCP plus the TLS layer for https proxies, producing
// the connection a CONNECT request can be written to. It is what WebSocket
// upgrades use; the HTTP transport instead relies on net/http calling
// DialTLSContext (see tlsDial) so the two trust anchors stay separate.
func (r *Registry) dialProxyHop(p *brokercore.UpstreamProxy) func(ctx context.Context, network, addr string) (net.Conn, error) {
	tcp := r.proxyTCP(p)
	proxyTLS := r.proxyTLSConfig(p)

	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		conn, err := tcp(ctx, network, "")
		if err != nil {
			return nil, err
		}
		if p.Scheme != brokercore.UpstreamProxySchemeHTTPS {
			return conn, nil
		}
		tlsConn := tls.Client(conn, proxyTLS.Clone())
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: TLS handshake with profile %q (%s): %w", ErrProxyUnreachable, p.Name, p.Host, err)
		}
		return tlsConn, nil
	}
}

// proxyTLSConfig anchors trust for the proxy hop in the certificate the
// operator pinned on the profile, falling back to the system pool when none
// is pinned.
func (r *Registry) proxyTLSConfig(p *brokercore.UpstreamProxy) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pool := rootPool(p.ProxyCAPEM); pool != nil {
		cfg.RootCAs = pool
	}
	if host, _, err := net.SplitHostPort(p.Host); err == nil {
		cfg.ServerName = host
	}
	return cfg
}

// proxyOrDirect adapts dialProxyHop for Transport.DialContext. When the
// Proxy hook declined (a no_proxy hit) net/http asks for the *target*
// address, and those requests must reach the network directly rather than
// being spoken to through the proxy — under the policy the un-proxied path
// would apply.
func (r *Registry) proxyOrDirect(p *brokercore.UpstreamProxy) func(ctx context.Context, network, addr string) (net.Conn, error) {
	hop := r.proxyTCP(p)
	direct := &net.Dialer{Timeout: proxyDialTimeout, KeepAlive: 30 * time.Second}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == p.Host {
			return hop(ctx, network, addr)
		}
		if r.validate {
			if err := netguard.ValidateTargetAddr(ctx, addr); err != nil {
				return nil, err
			}
		}
		return direct.DialContext(ctx, network, addr)
	}
}

// tlsDial provides the hop-level TLS handshake, mirroring what net/http does
// internally when no custom dialer is installed. Only the hop to the proxy
// changes: it is verified against the profile's pinned CA instead of the
// pool the upstream certificates are validated with. Targets — including
// targets reached through CONNECT — keep using the transport's own
// TLSClientConfig, so installing an egress proxy never widens trust in the
// upstream.
func (r *Registry) tlsDial(p *brokercore.UpstreamProxy, target *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	hop := r.proxyOrDirect(p)

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := hop(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		switch {
		case addr == p.Host:
			cfg = r.proxyTLSConfig(p)
		case target != nil:
			cfg = target.Clone()
		}
		if cfg.ServerName == "" {
			if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
				cfg.ServerName = host
			}
		}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("egress: TLS handshake with %q: %w", addr, err)
		}
		return tlsConn, nil
	}
}

// rootPool combines system roots with optional PEM-encoded extra roots used
// to validate the proxy's own certificate. Returns nil when no extra roots
// are configured so the platform pool stays in charge.
func rootPool(pem string) *x509.CertPool {
	if strings.TrimSpace(pem) == "" {
		return nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(pem)) {
		return nil
	}
	return pool
}

// socksDialer builds a SOCKS5 dialer from the profile, using x/net/proxy for
// the handshake (greeting, optional username/password sub-negotiation, and
// the request/reply exchange).
func (r *Registry) socksDialer(p *brokercore.UpstreamProxy) (proxy.Dialer, error) {
	var auth *proxy.Auth
	if p.HasAuth() {
		auth = &proxy.Auth{User: p.Username, Password: p.Password}
	}
	dialer, err := proxy.SOCKS5("tcp", p.Host, auth, proxyHopDialer(p))
	if err != nil {
		return nil, fmt.Errorf("egress: building socks5 dialer for profile %q: %w", p.Name, err)
	}
	return dialer, nil
}

// proxyHopDialer is the "how do I reach the proxy" half of a SOCKS profile.
// x/net/proxy uses it for the connection to the proxy itself, which is exactly
// the hop ErrProxyUnreachable describes; the target handshake happens later,
// inside the SOCKS request/reply exchange.
func proxyHopDialer(p *brokercore.UpstreamProxy) *hopDialer {
	dialer := &net.Dialer{Timeout: proxyDialTimeout}
	return &hopDialer{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, fmt.Errorf("%w: profile %q (%s): %w", ErrProxyUnreachable, p.Name, p.Host, err)
			}
			return conn, nil
		},
	}
}

// hopDialer adapts a plain function to proxy.ContextDialer.
type hopDialer struct {
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d *hopDialer) Dial(network, addr string) (net.Conn, error) {
	return d.dial(context.Background(), network, addr)
}

func (d *hopDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr)
}

// wrapTargetPolicy adapts a legacy single-flight SOCKS dialer to the
// context-aware hook net/http expects, applying network policy to the target
// first. Cancellation is cooperative: a cancelled context returns
// immediately while the in-flight dial is abandoned and closed by the caller.
func (r *Registry) wrapTargetPolicy(p *brokercore.UpstreamProxy, dialer proxy.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if r.validate {
			if err := netguard.ValidateTargetAddr(ctx, addr); err != nil {
				return nil, err
			}
		}
		type result struct {
			conn net.Conn
			err  error
		}
		done := make(chan result, 1)
		go func() {
			conn, err := dialer.Dial(network, addr)
			done <- result{conn: conn, err: err}
		}()
		select {
		case <-ctx.Done():
			// Close late arrivals so a slow proxy can't leak a socket.
			go func() {
				res := <-done
				if res.conn != nil {
					_ = res.conn.Close()
				}
			}()
			return nil, ctx.Err()
		case res := <-done:
			if res.err != nil {
				return nil, fmt.Errorf("egress: socks dial via profile %q: %w", p.Name, res.err)
			}
			return res.conn, nil
		}
	}
}

func (r *Registry) buildTunnel(p *brokercore.UpstreamProxy) (TunnelDialer, error) {
	switch p.Scheme {
	case brokercore.UpstreamProxySchemeSOCKS5, brokercore.UpstreamProxySchemeSOCKS5H:
		dialer, err := r.socksDialer(p)
		if err != nil {
			return nil, err
		}
		dial := r.wrapTargetPolicy(p, dialer)
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(ctx, network, addr)
		}, nil

	case brokercore.UpstreamProxySchemeHTTP, brokercore.UpstreamProxySchemeHTTPS:
		// Always the proxy hop: unlike the transport path, nothing has
		// decided whether to bypass yet, and a tunnel exists precisely
		// because the caller wants the target reached through the proxy.
		dialProxy := r.dialProxyHop(p)
		return func(ctx context.Context, _, addr string) (net.Conn, error) {
			if r.validate {
				if err := netguard.ValidateTargetAddr(ctx, addr); err != nil {
					return nil, err
				}
			}
			conn, err := dialProxy(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			if err := connectTunnel(ctx, conn, addr, p); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		}, nil

	default:
		return nil, fmt.Errorf("egress: unsupported upstream proxy scheme %q", p.Scheme)
	}
}

// connectTunnel issues CONNECT over an existing connection to the proxy and
// consumes the response. Authentication mirrors net/http's behaviour: the
// Proxy-Authorization header travels in the CONNECT request and never reaches
// the upstream.
func connectTunnel(ctx context.Context, conn net.Conn, addr string, p *brokercore.UpstreamProxy) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}
	var sb strings.Builder
	_, _ = sb.WriteString("CONNECT " + addr + " HTTP/1.1\r\n")
	_, _ = sb.WriteString("Host: " + addr + "\r\n")
	if p.HasAuth() {
		auth := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		_, _ = sb.WriteString("Proxy-Authorization: Basic " + auth + "\r\n")
	}
	_, _ = sb.WriteString("\r\n")
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return fmt.Errorf("egress: writing CONNECT to proxy %q: %w", p.Name, err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fmt.Errorf("egress: reading CONNECT response from proxy %q: %w", p.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("egress: proxy %q refused CONNECT with status %d", p.Name, resp.StatusCode)
	}
	return nil
}
