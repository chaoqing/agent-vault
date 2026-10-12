package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/egress"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/store"
)

// upstreamProxyCacheTTL bounds how long a resolved route is remembered. Most
// requests for the same service arrive in bursts, so this turns a burst into
// one lookup while keeping operator edits (which invalidate the cache
// explicitly) visible within seconds even if invalidation is missed.
const upstreamProxyCacheTTL = 5 * time.Second

// maxUpstreamProxyCacheEntries bounds the resolver cache so the map cannot
// grow without limit across vaults and service names even after entries
// expire (patience: a freshly-invalidated cache is rebuilt from scratch; the
// cap keeps steady-state memory flat).
const maxUpstreamProxyCacheEntries = 4096

// failOpenReplayBytes caps how much of a control-plane request body is held in
// memory purely so a fail_open profile can replay the request directly after a
// failed proxy hop. Above this the request keeps the "honour the proxy or
// fail" behaviour.
const failOpenReplayBytes = 8 << 20

// upstreamProxyResolver resolves the egress proxy for a single brokered
// request. Precedence is: the profile named by the matched service, then the
// instance default, then no proxy (direct connection), which is exactly what
// Agent Vault did before this feature existed.
//
// Nothing here is request-specific beyond the vault and matched service name,
// so results are cached briefly; see upstreamProxyCacheTTL.
type upstreamProxyResolver struct {
	s *Server

	mu    sync.RWMutex
	cache map[string]cachedUpstreamProxy
}

type cachedUpstreamProxy struct {
	proxy     *brokercore.UpstreamProxy
	expiresAt time.Time
}

// UpstreamProxyResolver returns the resolver injected into the MITM proxy. It
// stays live for the server's lifetime so profile edits take effect without a
// restart.
func (s *Server) UpstreamProxyResolver() brokercore.UpstreamProxyResolver {
	if s.upstreamRes == nil {
		s.upstreamRes = &upstreamProxyResolver{s: s, cache: make(map[string]cachedUpstreamProxy)}
	}
	return s.upstreamRes
}

// invalidateUpstreamProxyCache drops cached resolutions. Called after any
// administrative change so an edit applies to the very next request.
func (s *Server) invalidateUpstreamProxyCache() {
	if s.upstreamRes == nil {
		return
	}
	s.upstreamRes.mu.Lock()
	s.upstreamRes.cache = make(map[string]cachedUpstreamProxy)
	s.upstreamRes.mu.Unlock()
}

func (r *upstreamProxyResolver) ResolveUpstreamProxy(ctx context.Context, vaultID, serviceName string) (*brokercore.UpstreamProxy, error) {
	key := vaultID + "|" + serviceName

	r.mu.RLock()
	if cached, ok := r.cache[key]; ok && time.Now().Before(cached.expiresAt) {
		r.mu.RUnlock()
		return cached.proxy, nil
	}
	r.mu.RUnlock()

	proxy, err := r.resolve(ctx, vaultID, serviceName)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.setCacheLocked(key, proxy)
	r.mu.Unlock()
	return proxy, nil
}

// setCacheLocked stores key→proxy, enforcing maxUpstreamProxyCacheEntries.
// When the map is at capacity it first drops expired entries; if it is still
// at capacity (all entries live) it declines to cache rather than grow without
// bound. Callers hold r.mu.
func (r *upstreamProxyResolver) setCacheLocked(key string, proxy *brokercore.UpstreamProxy) {
	if len(r.cache) >= maxUpstreamProxyCacheEntries {
		// Opportunistic sweep of expired entries.
		now := time.Now()
		for k, v := range r.cache {
			if !now.Before(v.expiresAt) {
				delete(r.cache, k)
			}
		}
		if len(r.cache) >= maxUpstreamProxyCacheEntries {
			// Still full of live entries; skipping the write is better than
			// unbounded growth. The entry just degrades to a per-request
			// resolution until an admin change rebuilds the cache.
			return
		}
	}
	r.cache[key] = cachedUpstreamProxy{proxy: proxy, expiresAt: time.Now().Add(upstreamProxyCacheTTL)}
}

func (r *upstreamProxyResolver) resolve(ctx context.Context, vaultID, serviceName string) (*brokercore.UpstreamProxy, error) {
	// 1. Per-service override wins.
	if serviceName != "" {
		name, err := r.serviceProxyName(ctx, vaultID, serviceName)
		if err != nil {
			return nil, err
		}
		if name != "" {
			p, err := r.s.store.GetUpstreamProxyByName(ctx, name)
			switch {
			case err == nil && p.Enabled:
				return r.toProfile(ctx, p)
			case errors.Is(err, sql.ErrNoRows):
				r.s.logger.Warn("service references a missing upstream proxy; falling back to instance default",
					slog.String("vault_id", vaultID),
					slog.String("service", serviceName),
					slog.String("profile", name))
			case err != nil:
				return nil, err
			default:
				// Profile exists but is disabled: honour the kill switch.
				r.s.logger.Warn("service references a disabled upstream proxy; falling back to instance default",
					slog.String("vault_id", vaultID),
					slog.String("service", serviceName),
					slog.String("profile", name))
			}
		}
	}

	// 2. Instance-level default covers control-plane traffic and services
	//    without an explicit override.
	def, err := r.s.store.GetDefaultUpstreamProxy(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return r.toProfile(ctx, def)
}

// serviceProxyName finds the egress proxy referenced by a named service. It
// reads the vault's broker config the same way the service handlers do, so
// there is exactly one interpretation of "the services for this vault".
func (r *upstreamProxyResolver) serviceProxyName(ctx context.Context, vaultID, serviceName string) (string, error) {
	bc, err := r.s.store.GetBrokerConfig(ctx, vaultID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	if bc == nil || bc.ServicesJSON == "" {
		return "", nil
	}
	var services []broker.Service
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &services); err != nil {
		return "", err
	}
	// Normalize names the same way the service handlers do so a stored
	// service with an empty Name still matches by its assigned slug.
	broker.AssignSlugNames(services)
	for _, svc := range services {
		if svc.Name == serviceName && svc.UpstreamProxy != "" {
			return svc.UpstreamProxy, nil
		}
	}
	return "", nil
}

// toProfile decrypts stored proxy credentials into the runtime profile. The
// plaintext exists only in memory and only long enough to open a socket.
func (r *upstreamProxyResolver) toProfile(ctx context.Context, p *store.UpstreamProxy) (*brokercore.UpstreamProxy, error) {
	_ = ctx
	profile := &brokercore.UpstreamProxy{
		Name:       p.Name,
		Scheme:     p.Scheme,
		Host:       p.Host,
		NoProxy:    p.NoProxy,
		ProxyCAPEM: p.ProxyCAPEM,
		OnFailure:  p.OnFailure,
	}
	if len(p.UsernameCT) > 0 {
		user, err := crypto.Decrypt(p.UsernameCT, p.UsernameNonce, r.s.encKey)
		if err != nil {
			return nil, err
		}
		profile.Username = string(user)
		crypto.WipeBytes(user)
	}
	if len(p.PasswordCT) > 0 {
		pass, err := crypto.Decrypt(p.PasswordCT, p.PasswordNonce, r.s.encKey)
		if err != nil {
			return nil, err
		}
		profile.Password = string(pass)
		crypto.WipeBytes(pass)
	}
	return profile, nil
}

// --- Control-plane egress ---
//
// Requests the server makes on its own behalf (OAuth token exchanges, SMTP
// notifications, external secret-store syncs) are not brokered services, so
// there is no matched service to consult: they always use the instance
// default profile. They still route through the same egress machinery so an
// operator's "everything leaves through this proxy" promise holds for the
// whole process.

// egressRoundTripper picks a transport per request from the instance default
// profile. Without a default profile every request uses the caller's base
// transport, which keeps today's behaviour for operators who configure
// nothing.
type egressRoundTripper struct {
	base     *http.Transport
	resolver brokercore.UpstreamProxyResolver
	registry *egress.Registry
	logger   *slog.Logger
}

func (t *egressRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	profile, err := t.resolver.ResolveUpstreamProxy(req.Context(), "", "")
	if err != nil {
		// A resolution failure is a broker-side fault, not a licence to
		// route around the egress policy. Returning the error keeps the
		// operator's fail_closed promise intact instead of silently
		// dialling directly.
		return nil, fmt.Errorf("control-plane egress resolution failed: %w", err)
	}
	if profile == nil {
		// No default profile configured: direct is the pre-feature
		// behaviour and is exactly right.
		return t.base.RoundTrip(req)
	}
	if egress.Bypass(profile.NoProxy, req.URL.Host) {
		return t.base.RoundTrip(req)
	}
	transport, err := t.registry.Transport(profile)
	if err != nil {
		if profile.FailureMode() != brokercore.UpstreamProxyFailOpen {
			// fail_closed: an unusable proxy must not silently leak a
			// control-plane request onto a direct connection.
			return nil, fmt.Errorf("control-plane egress proxy %q is unusable: %w", profile.Name, err)
		}
		t.logger.Warn("control-plane egress proxy unusable; dialling directly under fail_open",
			slog.String("profile", profile.Name),
			slog.String("host", req.URL.Host),
			slog.String("error", err.Error()))
		return t.base.RoundTrip(req)
	}
	resp, err := transport.RoundTrip(req)
	// Only failures tagged as reaching *the proxy itself* are eligible for the
	// fail_open fallback; anything else (upstream TLS, DNS at the target) is
	// returned untouched so a proxy-side success can never become a hint to
	// bypass policy.
	if err == nil || profile.FailureMode() != brokercore.UpstreamProxyFailOpen ||
		!errors.Is(err, egress.ErrProxyUnreachable) {
		return resp, err
	}
	if !t.replayableBody(req) {
		return resp, err
	}
	t.logger.Warn("control-plane egress proxy unreachable; dialling directly under fail_open",
		slog.String("profile", profile.Name),
		slog.String("host", req.URL.Host),
		slog.String("error", err.Error()))
	return t.base.RoundTrip(req)
}

// replayableBody reports whether req's body can be sent a second time. Control
// plane calls are small, so bodies are buffered when they are small enough and
// never replayed when chunked or oversized — a half-sent re-dial is worse than
// an honest failure.
func (t *egressRoundTripper) replayableBody(req *http.Request) bool {
	if req.Body == nil {
		return true
	}
	if req.GetBody != nil {
		return true
	}
	if req.ContentLength < 0 || req.ContentLength > failOpenReplayBytes {
		return false
	}
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return false
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(data))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	return true
}

// ControlPlaneRoundTripper wraps base so control-plane HTTP calls honour the
// instance default egress proxy.
func (s *Server) ControlPlaneRoundTripper(base *http.Transport) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport).Clone()
		base.DialContext = netguard.SafeDialContext(netguard.AllowPrivateFromEnv())
	}
	return &egressRoundTripper{
		base:     base,
		resolver: s.UpstreamProxyResolver(),
		registry: s.controlPlaneEgress(),
		logger:   s.logger,
	}
}

// controlPlaneEgress returns the registry shared by control-plane callers.
// Direct and proxied transports share the caller's tuning because each base
// transport is cloned on use.
func (s *Server) controlPlaneEgress() *egress.Registry {
	s.controlPlaneOnce.Do(func() {
		s.controlPlaneRegistry = egress.NewRegistry(func() *http.Transport {
			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.DialContext = netguard.SafeDialContext(netguard.AllowPrivateFromEnv())
			return tr
		}, s.logger, true)
	})
	return s.controlPlaneRegistry
}

// controlPlaneDial returns the SMTP connection factory: SOCKS5 profiles are
// tunnelled, everything else dials directly. SMTP over an HTTP CONNECT proxy
// is not supported — email submission through a CONNECT tunnel would need its
// own CONNECT handshake in this package, and the practical combinations here
// are direct SMTP or SOCKS5.
func (s *Server) controlPlaneDial() func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		profile, err := s.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "", "")
		if err != nil {
			return nil, fmt.Errorf("control-plane egress resolution failed: %w", err)
		}
		if profile == nil {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.Background(), network, addr)
		}
		if profile.Scheme != brokercore.UpstreamProxySchemeSOCKS5 && profile.Scheme != brokercore.UpstreamProxySchemeSOCKS5H {
			// SMTP cannot ride an HTTP CONNECT proxy in this release. Dialling
			// directly here would silently bypass the egress policy for email
			// (case approvals, invites): under fail_closed that is exactly the
			// path an enforced-egress deployment exists to seal, so refuse.
			if profile.FailureMode() == brokercore.UpstreamProxyFailClosed {
				s.logger.Error("SMTP cannot use an HTTP upstream proxy; refusing to dial directly under fail_closed",
					slog.String("profile", profile.Name),
					slog.String("scheme", profile.Scheme))
				return nil, fmt.Errorf("egress: SMTP cannot be sent through %q proxy profile %q (scheme %s); refusing to bypass egress under fail_closed",
					profile.Scheme, profile.Name, profile.Scheme)
			}
			s.logger.Warn("SMTP cannot use an HTTP upstream proxy; dialling directly under fail_open",
				slog.String("profile", profile.Name),
				slog.String("scheme", profile.Scheme))
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.Background(), network, addr)
		}
		tunnel, err := s.controlPlaneEgress().Tunnel(profile)
		if err != nil {
			return nil, err
		}
		return tunnel(context.Background(), network, addr)
	}
}
