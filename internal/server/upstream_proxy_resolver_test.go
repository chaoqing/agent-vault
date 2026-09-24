package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
