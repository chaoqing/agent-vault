package egress

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/egress/egresstest"
)

// baseFactory mirrors how mitm.Proxy supplies its direct-connection
// transport: one fresh instance per build, carrying whatever TLS settings
// the caller pins.
func baseFactory(rootCAs *x509.CertPool) TransportFactory {
	return func() *http.Transport {
		return &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs},
		}
	}
}

func testProfile(name, scheme, host string) *brokercore.UpstreamProxy {
	return &brokercore.UpstreamProxy{Name: name, Scheme: scheme, Host: host}
}

// proxyRoundTrip is everything a caller may keep once a request completes. The
// body is drained and closed by the round-trip helper itself, so the many tests
// that discard the whole result in order to assert on the error alone can never
// leak a connection.
type proxyRoundTrip struct {
	StatusCode int
	Header     http.Header
	Body       string
}

// roundTripGET performs one GET through the profile and returns whatever the
// upstream served, so failures can be asserted on either side.
func roundTripGET(t *testing.T, p *brokercore.UpstreamProxy, rootCAs *x509.CertPool, rawURL string) (proxyRoundTrip, error) {
	t.Helper()
	return roundTripWithTimeout(t, p, rootCAs, rawURL, 10*time.Second)
}

func roundTripWithTimeout(t *testing.T, p *brokercore.UpstreamProxy, rootCAs *x509.CertPool, rawURL string, timeout time.Duration) (proxyRoundTrip, error) {
	t.Helper()
	r := NewRegistry(baseFactory(rootCAs), nil, true)
	tr, err := r.Transport(p)
	if err != nil {
		return proxyRoundTrip{}, err
	}
	client := &http.Client{Transport: tr, Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return proxyRoundTrip{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}
	return proxyRoundTrip{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(body)}, nil
}

func TestValidateRejectsUnusableProfiles(t *testing.T) {
	tests := []struct {
		name    string
		profile *brokercore.UpstreamProxy
	}{
		{"nil profile", nil},
		{"unknown scheme", testProfile("p", "ftp", "127.0.0.1:3128")},
		{"empty scheme", testProfile("p", "", "127.0.0.1:3128")},
		{"missing port", testProfile("p", brokercore.UpstreamProxySchemeHTTP, "127.0.0.1")},
		{"empty host", testProfile("p", brokercore.UpstreamProxySchemeHTTP, "")},
		{"unknown failure policy", &brokercore.UpstreamProxy{
			Name: "p", Scheme: brokercore.UpstreamProxySchemeHTTP, Host: "127.0.0.1:3128", OnFailure: "maybe"}},
		{"host carries a path", testProfile("p", brokercore.UpstreamProxySchemeHTTP, "127.0.0.1:3128/path")},
		{"host smuggles userinfo", testProfile("p", brokercore.UpstreamProxySchemeHTTP, "user@127.0.0.1:3128")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(tc.profile); err == nil {
				t.Fatalf("Validate(%+v) = nil, want error", tc.profile)
			}
		})
	}
}

func TestValidateAcceptsEverySupportedScheme(t *testing.T) {
	for _, scheme := range []string{
		brokercore.UpstreamProxySchemeHTTP,
		brokercore.UpstreamProxySchemeHTTPS,
		brokercore.UpstreamProxySchemeSOCKS5,
		brokercore.UpstreamProxySchemeSOCKS5H,
	} {
		p := testProfile("p", scheme, "proxy.internal:3128")
		if err := Validate(p); err != nil {
			t.Errorf("Validate(scheme=%s) = %v, want nil", scheme, err)
		}
	}
}

func TestValidateDefaultsFailureModeToFailClosed(t *testing.T) {
	p := testProfile("p", brokercore.UpstreamProxySchemeHTTP, "proxy.internal:3128")
	if got := p.FailureMode(); got != brokercore.UpstreamProxyFailClosed {
		t.Fatalf("FailureMode() = %q, want %q", got, brokercore.UpstreamProxyFailClosed)
	}
}

func TestBypassNoProxyMatrix(t *testing.T) {
	tests := []struct {
		name     string
		noProxy  string
		target   string
		wantSkip bool
	}{
		{"empty list proxies everything", "", "example.com:443", false},
		{"exact host", "example.com", "example.com:443", true},
		{"exact host with port on target ignored", "example.com", "example.com:8443", true},
		{"different host", "example.com", "api.anthropic.com:443", false},
		{"leading dot suffix", ".example.com", "api.example.com:443", true},
		{"leading dot does not match apex", ".example.com", "example.com:443", false},
		{"wildcard prefix", "*.example.com", "api.example.com:443", true},
		// NO_PROXY is a suffix match, matching curl and Go's own
		// httpproxy: one entry covers every level of subdomain.
		{"wildcard covers deeper subdomains", "*.example.com", "a.b.example.com:443", true},
		{"wildcard does not match apex", "*.example.com", "example.com:443", false},
		{"wildcard alone", "*", "anything.example.com:443", true},
		{"entry with matching port", "example.com:443", "example.com:443", true},
		{"entry with different port", "example.com:443", "example.com:80", false},
		{"entry port vs bare target", "example.com:443", "example.com", false},
		{"second entry of a list", "one.com, two.com", "two.com:443", true},
		{"whitespace tolerated", " one.com , two.com ", "two.com:443", true},
		{"case insensitive", "EXAMPLE.COM", "example.com:443", true},
		{"trailing dot normalised", "example.com", "example.com.:443", true},
		{"partial suffix is not a match", "ample.com", "example.com:443", false},
		{"bypass entry that is itself a suffix of nothing", "example.com", "notexample.com:443", false},
		{"empty target with a list", "example.com", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Bypass(tc.noProxy, tc.target); got != tc.wantSkip {
				t.Fatalf("Bypass(%q, %q) = %v, want %v", tc.noProxy, tc.target, got, tc.wantSkip)
			}
		})
	}
}

func TestFingerprintTracksEveryCredentialField(t *testing.T) {
	base := testProfile("p", brokercore.UpstreamProxySchemeHTTP, "proxy.internal:3128")
	mutations := map[string]func(p *brokercore.UpstreamProxy){
		"name":       func(p *brokercore.UpstreamProxy) { p.Name = "other" },
		"scheme":     func(p *brokercore.UpstreamProxy) { p.Scheme = brokercore.UpstreamProxySchemeHTTPS },
		"host":       func(p *brokercore.UpstreamProxy) { p.Host = "proxy.internal:3129" },
		"username":   func(p *brokercore.UpstreamProxy) { p.Username = "u" },
		"password":   func(p *brokercore.UpstreamProxy) { p.Password = "s" },
		"no_proxy":   func(p *brokercore.UpstreamProxy) { p.NoProxy = "example.com" },
		"proxy ca":   func(p *brokercore.UpstreamProxy) { p.ProxyCAPEM = "-----BEGIN CERTIFICATE-----\n" },
		"on_failure": func(p *brokercore.UpstreamProxy) { p.OnFailure = brokercore.UpstreamProxyFailOpen },
	}

	same := testProfile("p", brokercore.UpstreamProxySchemeHTTP, "proxy.internal:3128")
	if base.Fingerprint() != same.Fingerprint() {
		t.Fatal("identical profiles must share a fingerprint; the registry cache depends on it")
	}

	for field, mutate := range mutations {
		t.Run("changed "+field, func(t *testing.T) {
			edited := testProfile("p", brokercore.UpstreamProxySchemeHTTP, "proxy.internal:3128")
			mutate(edited)
			if base.Fingerprint() == edited.Fingerprint() {
				t.Fatalf("changing %s must produce a new fingerprint, otherwise rotated credentials keep the cached transport", field)
			}
		})
	}
}

func TestRegistryCachesTransportPerFingerprint(t *testing.T) {
	r := NewRegistry(baseFactory(nil), nil, true)
	p := testProfile("p", brokercore.UpstreamProxySchemeHTTP, "127.0.0.1:3128")

	first, err := r.Transport(p)
	if err != nil {
		t.Fatalf("Transport: %v", err)
	}
	again, err := r.Transport(testProfile("p", brokercore.UpstreamProxySchemeHTTP, "127.0.0.1:3128"))
	if err != nil {
		t.Fatalf("Transport: %v", err)
	}
	if first != again {
		t.Fatal("identical profiles must reuse one transport so the hot path allocates nothing")
	}

	rotated := testProfile("p", brokercore.UpstreamProxySchemeHTTP, "127.0.0.1:3128")
	rotated.Password = "rotated"
	different, err := r.Transport(rotated)
	if err != nil {
		t.Fatalf("Transport: %v", err)
	}
	if first == different {
		t.Fatal("a rotated password must yield a fresh transport")
	}
	if len(r.transports) != 2 {
		t.Fatalf("cached transports = %d, want 2", len(r.transports))
	}
}

func TestRegistryConcurrentAccessIsRaceFree(t *testing.T) {
	r := NewRegistry(baseFactory(nil), nil, true)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			profile := testProfile(fmt.Sprintf("p%d", i%4), brokercore.UpstreamProxySchemeSOCKS5,
				fmt.Sprintf("127.0.0.1:%d", 1080+i%4))
			if _, err := r.Transport(profile); err != nil {
				t.Errorf("Transport: %v", err)
			}
			if _, err := r.Tunnel(profile); err != nil {
				t.Errorf("Tunnel: %v", err)
			}
			r.CloseIdleConnections()
		}(i)
	}
	wg.Wait()
}

func TestTransportErrorsOnNilAndUnsupportedProfile(t *testing.T) {
	r := NewRegistry(baseFactory(nil), nil, true)
	if _, err := r.Transport(nil); err == nil {
		t.Fatal("Transport(nil) must fail")
	}
	if _, err := r.Tunnel(nil); err == nil {
		t.Fatal("Tunnel(nil) must fail")
	}
	if _, err := r.Transport(testProfile("p", "gopher", "127.0.0.1:70")); err == nil {
		t.Fatal("Transport with an unsupported scheme must fail")
	}
}

// --- Transport behaviour against the local proxies ---
//
// These are the coverage rows from the plan's L2 matrix, asserted one layer
// lower: whether a given scheme can actually carry a request. The MITM-layer
// tests reuse the same fixtures with credentials in flight.

func upstreamTLS(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "reached")
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv, roots
}

func upstreamPlain(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "reached")
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// assertReachableThroughProxy performs the request and asserts the upstream
// answered.
func assertReachableThroughProxy(t *testing.T, p *brokercore.UpstreamProxy, rootCAs *x509.CertPool, rawURL string) {
	t.Helper()
	tripped, err := roundTripGET(t, p, rootCAs, rawURL)
	assertUpstreamReached(t, tripped, err)
}

func assertUpstreamReached(t *testing.T, tripped proxyRoundTrip, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("request through upstream proxy: %v", err)
	}
	if tripped.Body != "hello-from-upstream" {
		t.Fatalf("body = %q, want %q", tripped.Body, "hello-from-upstream")
	}
	if tripped.Header.Get("X-Upstream") != "reached" {
		t.Fatalf("X-Upstream = %q, want reached", tripped.Header.Get("X-Upstream"))
	}
}

// netguard blocks loopback unless tests opt in, exactly as it does for
// direct connections. Every upstream below is loopback.
func allowLoopbackTargets(t *testing.T) {
	t.Helper()
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
}

func TestHTTPSUpstreamViaHTTPProxy(t *testing.T) {
	allowLoopbackTargets(t)
	upstream, roots := upstreamTLS(t)
	proxy := egresstest.NewHTTPProxy(t, "", "")

	p := testProfile("http-proxy", brokercore.UpstreamProxySchemeHTTP, proxy.Addr())
	assertReachableThroughProxy(t, p, roots, upstream.URL+"/v1/messages")

	if got := proxy.LastConnect(); got != strings.TrimPrefix(upstream.URL, "https://") {
		t.Fatalf("proxy CONNECT target = %q, want upstream authority %q",
			got, strings.TrimPrefix(upstream.URL, "https://"))
	}
}

func TestPlainHTTPUpstreamViaHTTPProxyUsesAbsoluteForm(t *testing.T) {
	allowLoopbackTargets(t)
	upstream := upstreamPlain(t)
	proxy := egresstest.NewHTTPProxy(t, "", "")

	p := testProfile("http-proxy", brokercore.UpstreamProxySchemeHTTP, proxy.Addr())
	assertReachableThroughProxy(t, p, nil, upstream.URL+"/v1/messages")

	if got := proxy.ForwardCount(); got != 1 {
		t.Fatalf("proxy absolute-form forwards = %d, want 1", got)
	}
	if got := proxy.ConnectCount(); got != 0 {
		t.Fatalf("proxy CONNECT count = %d, want 0 for a plain HTTP target", got)
	}
}

func TestHTTPProxyCredentialsTravelInProxyAuthorization(t *testing.T) {
	allowLoopbackTargets(t)
	upstream := upstreamPlain(t)
	proxy := egresstest.NewHTTPProxy(t, "egress-user", "egress-pass")

	p := testProfile("auth-proxy", brokercore.UpstreamProxySchemeHTTP, proxy.Addr())
	p.Username = "egress-user"
	p.Password = "egress-pass"

	tripped, err := roundTripGET(t, p, nil, upstream.URL+"/")
	assertUpstreamReached(t, tripped, err)

	if !strings.HasPrefix(proxy.SeenProxyAuth(), "Basic ") {
		t.Fatalf("proxy saw header %q, want a Basic Proxy-Authorization", proxy.SeenProxyAuth())
	}
}

func TestHTTPProxyRejectsWrongCredentials(t *testing.T) {
	allowLoopbackTargets(t)
	upstream := upstreamPlain(t)
	proxy := egresstest.NewHTTPProxy(t, "egress-user", "egress-pass")

	p := testProfile("auth-proxy", brokercore.UpstreamProxySchemeHTTP, proxy.Addr())
	p.Username = "egress-user"
	p.Password = "wrong"

	tripped, err := roundTripGET(t, p, nil, upstream.URL+"/")
	if err != nil {
		return // a hard error is also an acceptable rejection
	}
	if tripped.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d (proxy must refuse the hop)", tripped.StatusCode, http.StatusProxyAuthRequired)
	}
	if proxy.ForwardCount() != 0 {
		t.Fatal("proxy must not forward a request whose credentials are wrong")
	}
}

func TestHTTPSUpstreamViaHTTPSProxyTrustsProfileCA(t *testing.T) {
	allowLoopbackTargets(t)
	upstream, roots := upstreamTLS(t)
	proxy := egresstest.NewHTTPSProxy(t, "", "")

	p := testProfile("tls-proxy", brokercore.UpstreamProxySchemeHTTPS, proxy.Addr())
	// Without the pinned CA the proxy handshake must fail.
	if _, err := roundTripGET(t, p, roots, upstream.URL+"/"); err == nil {
		t.Fatal("https proxy without the pinned CA must not be reachable")
	}

	p.ProxyCAPEM = proxy.PEM()
	tripped, err := roundTripGET(t, p, roots, upstream.URL+"/")
	assertUpstreamReached(t, tripped, err)
}

func TestUpstreamViaSOCKS5Proxy(t *testing.T) {
	allowLoopbackTargets(t)
	upstream := upstreamPlain(t)
	socks := egresstest.NewSOCKS5Proxy(t, "", "")

	p := testProfile("socks5", brokercore.UpstreamProxySchemeSOCKS5, socks.Addr())
	tripped, err := roundTripGET(t, p, nil, upstream.URL+"/")
	assertUpstreamReached(t, tripped, err)

	if got := socks.DialCount(); got != 1 {
		t.Fatalf("socks server saw %d CONNECTs, want 1", got)
	}
}

func TestUpstreamViaSOCKS5WithUsernamePassword(t *testing.T) {
	allowLoopbackTargets(t)
	upstream, roots := upstreamTLS(t)
	socks := egresstest.NewSOCKS5Proxy(t, "socks-user", "socks-pass")

	p := testProfile("socks5-auth", brokercore.UpstreamProxySchemeSOCKS5, socks.Addr())
	p.Username = "socks-user"
	p.Password = "socks-pass"

	tripped, err := roundTripGET(t, p, roots, upstream.URL+"/")
	assertUpstreamReached(t, tripped, err)
	if got := socks.DialCount(); got != 1 {
		t.Fatalf("socks server saw %d CONNECTs, want 1", got)
	}
}

func TestUpstreamViaSOCKS5RejectsWrongCredentials(t *testing.T) {
	allowLoopbackTargets(t)
	upstream := upstreamPlain(t)
	socks := egresstest.NewSOCKS5Proxy(t, "socks-user", "socks-pass")

	p := testProfile("socks5-auth", brokercore.UpstreamProxySchemeSOCKS5, socks.Addr())
	p.Username = "socks-user"
	p.Password = "wrong"

	if _, err := roundTripGET(t, p, nil, upstream.URL+"/"); err == nil {
		t.Fatal("socks5 handshake with wrong credentials must fail")
	}
}

// --- Security red line 1: policy is enforced before the proxy is dialled ---

func blockPrivateTargets(t *testing.T) {
	t.Helper()
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "false")
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "")
}

func TestBlockedTargetIsRejectedBeforeTheProxyIsContacted(t *testing.T) {
	blockPrivateTargets(t)
	proxy := egresstest.NewHTTPProxy(t, "", "")
	// Targets an operator policy forbids: an RFC-1918 address and the cloud
	// metadata endpoint. Reaching either through a proxy would make the
	// proxy an SSRF amplifier.
	targets := []string{"http://10.0.0.5:80/latest/meta-data", "http://192.168.1.1:80/", "http://169.254.169.254:80/latest"}

	for _, scheme := range []string{
		brokercore.UpstreamProxySchemeHTTP,
		brokercore.UpstreamProxySchemeSOCKS5,
		brokercore.UpstreamProxySchemeSOCKS5H,
	} {
		for _, target := range targets {
			t.Run(scheme+" -> "+target, func(t *testing.T) {
				blockPrivateTargets(t)
				p := testProfile("p", scheme, proxy.Addr())
				if _, err := roundTripGET(t, p, nil, target); err == nil {
					t.Fatalf("request to %s through %s must be refused by network policy", target, scheme)
				}
				if got := proxy.ConnectCount() + proxy.ForwardCount(); got != 0 {
					t.Fatalf("proxy observed %d requests to a blocked target; policy ran too late", got)
				}
			})
		}
	}
}

func TestSOCKS5ServerNeverSeesBlockedTarget(t *testing.T) {
	blockPrivateTargets(t)
	socks := egresstest.NewSOCKS5Proxy(t, "", "")
	p := testProfile("socks5", brokercore.UpstreamProxySchemeSOCKS5, socks.Addr())

	if _, err := roundTripGET(t, p, nil, "http://10.0.0.5:80/"); err == nil {
		t.Fatal("blocked target must not be reachable through socks5")
	}
	if got := socks.DialCount(); got != 0 {
		t.Fatalf("socks server saw %d CONNECTs for a blocked target, want 0", got)
	}
}

// --- Security red line 2: the proxy may live inside the blocked ranges ---

// An operator naming a proxy IS the authorisation to reach it, including when
// that proxy sits on an address the target policy would refuse. Only the
// upstream is allowlisted here — never the proxy.
func TestProxyOnNonAllowlistedAddressIsStillReachable(t *testing.T) {
	// Upstream lives on a second loopback address so it can be allowlisted
	// independently of the proxy's own 127.0.0.1 address.
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("this host cannot bind 127.0.0.2: %v", err)
	}
	upstream := &httptest.Server{
		Listener: l,
		Config: &http.Server{
			ReadHeaderTimeout: 10 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Upstream", "reached")
				_, _ = io.WriteString(w, "hello-from-upstream")
			}),
		},
	}
	upstream.Start()
	t.Cleanup(upstream.Close)

	proxy := egresstest.NewHTTPProxy(t, "", "")
	socks := egresstest.NewSOCKS5Proxy(t, "", "")

	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "false")
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "127.0.0.2/32")

	for _, tc := range []struct {
		name   string
		scheme string
	}{
		{"http", brokercore.UpstreamProxySchemeHTTP},
		{"socks5", brokercore.UpstreamProxySchemeSOCKS5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "false")
			t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "127.0.0.2/32")
			host := proxy.Addr()
			if tc.scheme == brokercore.UpstreamProxySchemeSOCKS5 {
				host = socks.Addr()
			}
			p := testProfile("private-proxy", tc.scheme, host)
			tripped, rerr := roundTripGET(t, p, nil, upstream.URL+"/")
			assertUpstreamReached(t, tripped, rerr)
		})
	}
}

// --- Tunnel dialer (WebSocket upgrades) ---

func TestTunnelDialerEstablishesCONNECTThroughHTTPProxy(t *testing.T) {
	allowLoopbackTargets(t)

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, aerr := echoLn.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = echoLn.Close() })

	proxy := egresstest.NewHTTPProxy(t, "tunnel-user", "tunnel-pass")
	p := testProfile("ws-proxy", brokercore.UpstreamProxySchemeHTTP, proxy.Addr())
	p.Username = "tunnel-user"
	p.Password = "tunnel-pass"

	r := NewRegistry(baseFactory(nil), nil, true)
	tunnel, err := r.Tunnel(p)
	if err != nil {
		t.Fatalf("Tunnel: %v", err)
	}
	conn, err := tunnel(t.Context(), "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("tunnel dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("upgrade-plz")); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, len("upgrade-plz"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echoed bytes: %v", err)
	}
	if string(buf) != "upgrade-plz" {
		t.Fatalf("echoed %q, want %q", string(buf), "upgrade-plz")
	}
	if got := proxy.ConnectCount(); got != 1 {
		t.Fatalf("proxy CONNECT count = %d, want 1", got)
	}
}

func TestTunnelDialerRespectsNetworkPolicy(t *testing.T) {
	blockPrivateTargets(t)
	proxy := egresstest.NewHTTPProxy(t, "", "")
	socks := egresstest.NewSOCKS5Proxy(t, "", "")

	for _, tc := range []struct {
		scheme string
		host   string
	}{
		{brokercore.UpstreamProxySchemeHTTP, proxy.Addr()},
		{brokercore.UpstreamProxySchemeSOCKS5, socks.Addr()},
	} {
		t.Run(tc.scheme, func(t *testing.T) {
			blockPrivateTargets(t)
			p := testProfile("ws-proxy", tc.scheme, tc.host)
			r := NewRegistry(baseFactory(nil), nil, true)
			tunnel, err := r.Tunnel(p)
			if err != nil {
				t.Fatalf("Tunnel: %v", err)
			}
			if _, err := tunnel(t.Context(), "tcp", "169.254.169.254:80"); err == nil {
				t.Fatal("tunnel to the metadata endpoint must be refused")
			}
		})
	}
}

func TestUnreachableProxySurfacesAnError(t *testing.T) {
	allowLoopbackTargets(t)
	upstream := upstreamPlain(t)
	blackhole := egresstest.NewBlackholeProxy(t)

	// A proxy that never answers must surface as an error quickly rather
	// than hanging the request.
	p := testProfile("dead-proxy", brokercore.UpstreamProxySchemeHTTP, blackhole.Addr())
	if _, err := roundTripWithTimeout(t, p, nil, upstream.URL+"/", 2*time.Second); err == nil {
		t.Fatal("a proxy that never answers must surface as an error, not a hang")
	}
	if got := blackhole.ConnectionCount(); got == 0 {
		t.Fatal("expected at least one connection attempt to the dead proxy")
	}
}
