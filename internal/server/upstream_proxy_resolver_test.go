package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/egress/egresstest"
	"github.com/Infisical/agent-vault/internal/store"
)

// Resolution precedence decides which proxy carries a request, and it has to
// fail safe: an operator edit or a deleted profile must degrade to a direct
// connection rather than becoming an outage or a silent re-route.

func seedProxy(t *testing.T, ms *mockStore, name, scheme, host string, isDefault, enabled bool) *store.UpstreamProxy {
	t.Helper()
	p := &store.UpstreamProxy{
		Name: name, Scheme: scheme, Host: host,
		OnFailure: "fail_closed", IsDefault: isDefault, Enabled: enabled,
	}
	if err := ms.CreateUpstreamProxy(context.Background(), p); err != nil {
		t.Fatalf("seed proxy: %v", err)
	}
	return ms.upstreamProxies[name]
}

// encryptInto stores encrypted credentials the way the admin handler does, so
// resolution exercises the real decryption path.
func encryptInto(t *testing.T, key []byte, p *store.UpstreamProxy, user, pass string) {
	t.Helper()
	uct, unonce, err := crypto.Encrypt([]byte(user), key)
	if err != nil {
		t.Fatalf("encrypt username: %v", err)
	}
	pct, pnonce, err := crypto.Encrypt([]byte(pass), key)
	if err != nil {
		t.Fatalf("encrypt password: %v", err)
	}
	p.UsernameCT, p.UsernameNonce = uct, unonce
	p.PasswordCT, p.PasswordNonce = pct, pnonce
}

func setServices(t *testing.T, ms *mockStore, vaultID string, services []broker.Service) {
	t.Helper()
	raw, err := marshalServices(services)
	if err != nil {
		t.Fatalf("marshal services: %v", err)
	}
	if _, err := ms.SetBrokerConfig(context.Background(), vaultID, raw); err != nil {
		t.Fatalf("set broker config: %v", err)
	}
}

func marshalServices(services []broker.Service) (string, error) {
	raw, err := json.Marshal(services)
	return string(raw), err
}

func TestResolverPrefersServiceProfileOverInstanceDefault(t *testing.T) {
	ms := newMockStore()
	defaultProxy := seedProxy(t, ms, "default-corp", "http", "default.proxy:3128", true, true)
	scoped := seedProxy(t, ms, "scoped-corp", "socks5", "scoped.proxy:1080", false, true)
	setServices(t, ms, "root-ns-id", []broker.Service{
		{Name: "anthropic", Host: "api.anthropic.com", UpstreamProxy: "scoped-corp"},
	})

	srv := newTestServer(withStore(ms))
	res := srv.UpstreamProxyResolver()

	got, err := res.ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil {
		t.Fatal("resolved nil for a service with an explicit proxy")
	}
	if got.Name != scoped.Name || got.Scheme != "socks5" {
		t.Fatalf("resolved %+v, want the service-scoped profile", got)
	}

	// A service without an override lands on the instance default.
	got, err = res.ResolveUpstreamProxy(context.Background(), "root-ns-id", "other")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil || got.Name != defaultProxy.Name {
		t.Fatalf("resolved %+v, want the instance default %q", got, defaultProxy.Name)
	}
}

func TestResolverReturnsNilWithoutAnyProfile(t *testing.T) {
	ms := newMockStore()
	srv := newTestServer(withStore(ms))

	got, err := srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != nil {
		t.Fatalf("resolved %+v, want nil (no default means direct)", got)
	}
}

func TestResolverFallsBackWhenReferencedProfileIsMissing(t *testing.T) {
	ms := newMockStore()
	seedProxy(t, ms, "default-corp", "http", "default.proxy:3128", true, true)
	setServices(t, ms, "root-ns-id", []broker.Service{
		{Name: "anthropic", Host: "api.anthropic.com", UpstreamProxy: "deleted-profile"},
	})

	srv := newTestServer(withStore(ms))
	got, err := srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil || got.Name != "default-corp" {
		t.Fatalf("resolved %+v, want fallback to the instance default", got)
	}
}

func TestResolverHonoursDisabledProfileAsKillSwitch(t *testing.T) {
	ms := newMockStore()
	seedProxy(t, ms, "default-corp", "http", "default.proxy:3128", true, true)
	seedProxy(t, ms, "off-corp", "http", "off.proxy:3128", false, false)
	setServices(t, ms, "root-ns-id", []broker.Service{
		{Name: "anthropic", Host: "api.anthropic.com", UpstreamProxy: "off-corp"},
	})

	srv := newTestServer(withStore(ms))
	got, err := srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil || got.Name != "default-corp" {
		t.Fatalf("resolved %+v, want fallback when the referenced profile is disabled", got)
	}

	// With no configured default, disabling is equivalent to going direct.
	ms.upstreamProxies["default-corp"].Enabled = false
	srv.invalidateUpstreamProxyCache()
	got, err = srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != nil {
		t.Fatalf("resolved %+v when every avenue is disabled, want nil", got)
	}
}

func TestResolverDecryptsCredentialsIntoTheProfile(t *testing.T) {
	ms := newMockStore()
	key := make([]byte, 32)
	p := seedProxy(t, ms, "auth-proxy", "http", "auth.proxy:3128", true, true)
	encryptInto(t, key, p, "svc-user", "svc-pass")

	srv := newTestServer(withStore(ms), withEncKey(key))
	got, err := srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil {
		t.Fatal("expected the default profile")
	}
	if got.Username != "svc-user" || got.Password != "svc-pass" {
		t.Fatalf("credentials = %q/%q, want decrypted values", got.Username, got.Password)
	}
}

func TestResolverFailsClosedOnUndecryptableProfile(t *testing.T) {
	ms := newMockStore()
	p := seedProxy(t, ms, "auth-proxy", "http", "auth.proxy:3128", true, true)
	encryptInto(t, keyA(t, 0xAA), p, "svc-user", "svc-pass")

	// A different key means the stored credentials cannot be opened. The
	// request must be refused rather than routed with missing credentials.
	srv := newTestServer(withStore(ms), withEncKey(keyA(t, 0xBB)))
	if _, err := srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic"); err == nil {
		t.Fatal("expected an error when proxy credentials cannot be decrypted")
	}
}

func TestResolverPropagatesStoreErrors(t *testing.T) {
	ms := newMockStore()
	srv := newTestServer(withStore(&failingProxyStore{mockStore: ms}))
	if _, err := srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic"); err == nil {
		t.Fatal("expected the store error to surface")
	}
}

// failingProxyStore makes every profile lookup fail, so the resolver can be
// observed degrading to "no route" instead of inventing one.
type failingProxyStore struct {
	*mockStore
}

func (s *failingProxyStore) GetDefaultUpstreamProxy(context.Context) (*store.UpstreamProxy, error) {
	return nil, errors.New("database is offline")
}

func TestResolverCacheServesRepeatedLookups(t *testing.T) {
	ms := newMockStore()
	seedProxy(t, ms, "default-corp", "http", "default.proxy:3128", true, true)
	srv := newTestServer(withStore(ms))
	res := srv.UpstreamProxyResolver()

	first, err := res.ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Edit behind the resolver's back; the cache should still serve until
	// invalidation, which is why the admin handlers call it explicitly.
	ms.upstreamProxies["default-corp"].Host = "changed.proxy:3128"
	cached, err := res.ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cached.Host != first.Host {
		t.Fatalf("cached host = %q, want %q from the cached entry", cached.Host, first.Host)
	}

	srv.invalidateUpstreamProxyCache()
	refreshed, err := res.ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if refreshed.Host != "changed.proxy:3128" {
		t.Fatalf("host after invalidation = %q, want the edited value", refreshed.Host)
	}
}

func TestResolverCacheExpires(t *testing.T) {
	ms := newMockStore()
	seedProxy(t, ms, "default-corp", "http", "default.proxy:3128", true, true)
	srv := newTestServer(withStore(ms))
	res := srv.UpstreamProxyResolver().(*upstreamProxyResolver)

	res.mu.Lock()
	res.cache["root-ns-id|anthropic"] = cachedUpstreamProxy{
		proxy:     &brokercore.UpstreamProxy{Name: "stale", Scheme: "http", Host: "stale.proxy:3128"},
		expiresAt: time.Now().Add(-time.Second),
	}
	res.mu.Unlock()

	got, err := res.ResolveUpstreamProxy(context.Background(), "root-ns-id", "anthropic")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Name != "default-corp" {
		t.Fatalf("resolved %+v; an expired entry must not be served", got)
	}
}

func TestResolverCacheBounded(t *testing.T) {
	srv := newTestServer(withStore(newMockStore()))
	res := srv.UpstreamProxyResolver().(*upstreamProxyResolver)

	res.mu.Lock()
	// Fill to capacity with live (unexpired) entries.
	for i := 0; i < maxUpstreamProxyCacheEntries; i++ {
		res.cache[fmt.Sprintf("v%d|s%d", i, i)] = cachedUpstreamProxy{
			proxy:     &brokercore.UpstreamProxy{Name: "p", Scheme: "http", Host: "a:3128"},
			expiresAt: time.Now().Add(time.Hour),
		}
	}
	// At capacity with all entries live, a new key must be declined rather
	// than growing the map without bound.
	res.setCacheLocked("v|extra", &brokercore.UpstreamProxy{Name: "p", Scheme: "http", Host: "a:3128"})
	if _, ok := res.cache["v|extra"]; ok {
		t.Fatal("cache grew beyond maxUpstreamProxyCacheEntries with all entries live")
	}
	if len(res.cache) > maxUpstreamProxyCacheEntries {
		t.Fatalf("cache len = %d, want <= %d", len(res.cache), maxUpstreamProxyCacheEntries)
	}

	// But an expired entry first makes room: dropping it lets the new key in.
	for k, v := range res.cache {
		v.expiresAt = time.Now().Add(-time.Second)
		res.cache[k] = v
	}
	// Patch one entry back to live so len drops by one after the sweep.
	live := false
	for k := range res.cache {
		_ = k
		if !live {
			res.cache[k] = cachedUpstreamProxy{proxy: &brokercore.UpstreamProxy{Name: "p", Scheme: "http", Host: "a:3128"}, expiresAt: time.Now().Add(time.Hour)}
			live = true
		}
	}
	res.setCacheLocked("v|extra", &brokercore.UpstreamProxy{Name: "p", Scheme: "http", Host: "a:3128"})
	if _, ok := res.cache["v|extra"]; !ok {
		t.Fatal("after expiring entries make room, a new key should be cached")
	}
	if len(res.cache) > maxUpstreamProxyCacheEntries {
		t.Fatalf("cache len = %d, want <= %d", len(res.cache), maxUpstreamProxyCacheEntries)
	}
	res.mu.Unlock()
}

func TestResolverMatchesServiceByAssignedSlug(t *testing.T) {
	ms := newMockStore()
	seedProxy(t, ms, "corp", "http", "corp.proxy:3128", false, true)
	srv := newTestServer(withStore(ms))

	const host = "api.anthropic.com"
	slug := broker.Slugify(host, "", nil)
	if slug == "" {
		t.Fatalf("Slugify(%q) produced an empty slug", host)
	}

	// A stored service with an empty Name (legacy data) carries an upstream
	// proxy reference. The resolver must still match it via the slug the
	// service handlers assign, not silently fall through to the instance
	// default (which is absent here → direct).
	setServices(t, ms, "root-ns-id", []broker.Service{
		{Name: "", Host: host, Auth: broker.Auth{Type: "passthrough"}, UpstreamProxy: "corp"},
	})

	res := srv.UpstreamProxyResolver()
	got, err := res.ResolveUpstreamProxy(context.Background(), "root-ns-id", slug)
	if err != nil {
		t.Fatalf("resolve by slug %q: %v", slug, err)
	}
	if got == nil {
		t.Fatal("expected the corp profile for the slug-matched service; got nil (direct)")
	}
	if got.Name != "corp" {
		t.Fatalf("resolved profile = %q, want corp", got.Name)
	}
}

func TestControlPlaneRoundTripperUsesDefaultProfile(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")

	ms := newMockStore()
	egressProxy := egresstest.NewHTTPProxy(t, "", "")
	p := seedProxy(t, ms, "default-corp", "http", egressProxy.Addr(), true, true)
	_ = p

	srv := newTestServer(withStore(ms))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	rt := srv.ControlPlaneRoundTripper(nil)
	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/oauth/token", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("control-plane request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-from-upstream" {
		t.Fatalf("body = %q, want the upstream response", string(body))
	}
	if got := egressProxy.ForwardCount(); got != 1 {
		t.Fatalf("egress proxy forwards = %d, want 1; control-plane traffic must honour the default profile", got)
	}
}

func TestControlPlaneRoundTripperHonoursNoProxy(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")

	ms := newMockStore()
	egressProxy := egresstest.NewHTTPProxy(t, "", "")
	seedProxy(t, ms, "default-corp", "http", egressProxy.Addr(), true, true).NoProxy = "127.0.0.1"

	srv := newTestServer(withStore(ms))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	rt := srv.ControlPlaneRoundTripper(nil)
	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/oauth/token", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("control-plane request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := egressProxy.RequestCount(); got != 0 {
		t.Fatalf("egress proxy saw %d requests for a no_proxy host, want 0", got)
	}
}

// H1: an unusable default profile must not silently drop the control plane onto
// a direct connection. Under fail_closed the request fails closed instead.
func TestControlPlaneRoundTripperFailsClosedOnUnusableProfile(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")

	var reached int32
	ms := newMockStore()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reached, 1)
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()
	// A host without a port can never be turned into a dialler.
	seedProxy(t, ms, "broken", "http", "proxy.internal", true, true)

	srv := newTestServer(withStore(ms))
	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/oauth/token", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if _, err := srv.ControlPlaneRoundTripper(nil).RoundTrip(req); err == nil {
		t.Fatal("control-plane request succeeded through an unusable proxy; fail_closed must refuse it")
	}
	if got := atomic.LoadInt32(&reached); got != 0 {
		t.Fatalf("upstream was reached %d times; the unusable proxy must not degrade to direct under fail_closed", got)
	}
}

// H1: under fail_open the same unusable profile may fall back to a direct
// connection.
func TestControlPlaneRoundTripperFailsOpenOnUnusableProfile(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")

	ms := newMockStore()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()
	broken := seedProxy(t, ms, "broken", "http", "proxy.internal", true, true)
	broken.OnFailure = brokercore.UpstreamProxyFailOpen

	srv := newTestServer(withStore(ms))
	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/oauth/token", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.ControlPlaneRoundTripper(nil).RoundTrip(req)
	if err != nil {
		t.Fatalf("fail_open should fall back to a direct dial, got: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-from-upstream" {
		t.Fatalf("body = %q, want the direct upstream response", string(body))
	}
}

// H2: a fail_open default proxy that is unreachable must fall back to a direct
// dial; the control plane honours fail_open just like the MITM data plane.
func TestControlPlaneRoundTripperFailsOpenWhenProxyUnreachable(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")

	ms := newMockStore()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	egressProxy := egresstest.NewHTTPProxy(t, "", "")
	p := seedProxy(t, ms, "default-corp", "http", egressProxy.Addr(), true, true)
	p.OnFailure = brokercore.UpstreamProxyFailOpen

	srv := newTestServer(withStore(ms))
	rt := srv.ControlPlaneRoundTripper(nil)

	// Proxy alive: traffic goes through it.
	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/oauth/token", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("control-plane request: %v", err)
	}
	_ = resp.Body.Close()
	if got := egressProxy.RequestCount(); got != 1 {
		t.Fatalf("egress proxy forwards = %d, want 1 while proxy is up", got)
	}

	// Proxy gone: fail_open falls back to a direct dial and still succeeds.
	egressProxy.Close()
	req2, err := http.NewRequest(http.MethodGet, upstream.URL+"/oauth/token", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp2, err := rt.RoundTrip(req2)
	if err != nil {
		t.Fatalf("fail_open should fall back to direct when the proxy is unreachable, got: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	body, _ := io.ReadAll(resp2.Body)
	if string(body) != "hello-from-upstream" {
		t.Fatalf("body = %q, want the direct upstream response", string(body))
	}
}

// H3: SMTP through a non-SOCKS default profile must not silently dial directly
// under fail_closed — approvals and invites would leak past the egress policy.
func TestControlPlaneDialRefusesHTTPProxyUnderFailClosed(t *testing.T) {
	ms := newMockStore()
	seedProxy(t, ms, "http-default", "http", "proxy.internal:3128", true, true)

	srv := newTestServer(withStore(ms))
	// A live listener proves any direct dial would succeed; the point is that
	// controlPlaneDial refuses to even try it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	_, err = srv.controlPlaneDial()("tcp", ln.Addr().String())
	if err == nil {
		t.Fatal("SMTP dial succeeded through an http proxy profile; fail_closed must refuse to bypass egress")
	}
	if !strings.Contains(err.Error(), "fail_closed") {
		t.Fatalf("SMTP error = %v, want an explicit fail_closed refusal message", err)
	}
}

// H3: under fail_open the same non-SOCKS profile may dial directly, mirroring
// the fail_open promise that the proxy's absence is not an outage.
func TestControlPlaneDialFallsBackDirectlyUnderFailOpen(t *testing.T) {
	ms := newMockStore()
	p := seedProxy(t, ms, "http-default", "http", "proxy.internal:3128", true, true)
	p.OnFailure = brokercore.UpstreamProxyFailOpen

	srv := newTestServer(withStore(ms))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	conn, err := srv.controlPlaneDial()("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("SMTP dial should fall back to direct under fail_open, got: %v", err)
	}
	_ = conn.Close()
}

func keyA(t *testing.T, fill byte) []byte {
	t.Helper()
	k := make([]byte, 32)
	for i := range k {
		k[i] = fill
	}
	return k
}

func TestServiceWriteRejectsUnknownUpstreamProxyReference(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"anthropic","host":"api.anthropic.com","auth":{"type":"passthrough"},"upstream_proxy":"ghost"}]}`
	rec := proxyRequest(t, srv, http.MethodPut, "/v1/vaults/default/services", ownerToken, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("config write referencing an unknown proxy = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ghost") {
		t.Fatalf("error must name the unknown profile: %s", rec.Body.String())
	}
	if _, ok := ms.brokerConfigs["root-ns-id"]; ok {
		t.Fatalf("broker config was written despite an invalid proxy reference")
	}
}

func TestServiceWriteAcceptsKnownUpstreamProxyReference(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	seedProxy(t, ms, "corp", "http", "proxy.internal:3128", false, true)

	body := `{"services":[{"name":"anthropic","host":"api.anthropic.com","auth":{"type":"passthrough"},"upstream_proxy":"corp"}]}`
	rec := proxyRequest(t, srv, http.MethodPut, "/v1/vaults/default/services", ownerToken, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("config write = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestServiceJSONRoundTripPreservesUpstreamProxyName(t *testing.T) {
	// Guards the JSON contract the UI and proposals rely on.
	raw := `{"name":"anthropic","host":"api.anthropic.com","upstream_proxy":"corp"}`
	var svc broker.Service
	if err := json.Unmarshal([]byte(raw), &svc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if svc.UpstreamProxy != "corp" {
		t.Fatalf("UpstreamProxy = %q, want corp", svc.UpstreamProxy)
	}
	again, err := json.Marshal(svc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(again), `"upstream_proxy":"corp"`) {
		t.Fatalf("round-tripped %s, want the upstream_proxy field preserved", string(again))
	}
}

func TestValidateUpstreamProxyNameRejectsInjectionCharacters(t *testing.T) {
	valid := []string{"corp", "corp-proxy", "Corp_Proxy.1"}
	for _, name := range valid {
		if err := broker.ValidateUpstreamProxyName(name); err != nil {
			t.Errorf("ValidateUpstreamProxyName(%q) = %v, want nil", name, err)
		}
	}
	invalid := []string{
		strings.Repeat("a", 65),
		"proxy 01",
		"corp/proxy",
		`corp"proxy`,
		"corp\\proxy",
		"corp@proxy",
		"corp:proxy",
		"corp#proxy",
		"corp\rproxy",
		"corp\nproxy",
	}
	for _, name := range invalid {
		if err := broker.ValidateUpstreamProxyName(name); err == nil {
			t.Errorf("ValidateUpstreamProxyName(%q) = nil, want error", name)
		}
	}
}
