package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

// The upstream proxy API is admin-only surface that decides where an agent's
// traffic goes once credentials have been injected. These tests cover the
// authorisation boundary, input validation, secret handling, and the
// reference-count guard that keeps a deletion from silently re-routing live
// traffic.

func proxyRequest(t *testing.T, srv *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, r)
	return rec
}

func decodeProxyView(t *testing.T, rec *httptest.ResponseRecorder) proxyView {
	t.Helper()
	var resp struct {
		Proxy proxyView `json:"proxy"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode proxy view: %v (body %s)", err, rec.Body.String())
	}
	return resp.Proxy
}

func TestUpstreamProxyEndpointsRequireOwner(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms)
	srv := newTestServer(withStore(ms))

	if err := ms.CreateUpstreamProxy(t.Context(), &store.UpstreamProxy{
		Name: "corp", Scheme: "http", Host: "proxy.internal:3128", OnFailure: "fail_closed", Enabled: true,
	}); err != nil {
		t.Fatalf("seed proxy: %v", err)
	}

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"list", http.MethodGet, "/v1/admin/upstream-proxies", ""},
		{"create", http.MethodPost, "/v1/admin/upstream-proxies", `{"name":"x","scheme":"http","host":"h:1","on_failure":"fail_closed"}`},
		{"get", http.MethodGet, "/v1/admin/upstream-proxies/corp", ""},
		{"update", http.MethodPatch, "/v1/admin/upstream-proxies/corp", `{"host":"proxy.internal:3129"}`},
		{"delete", http.MethodDelete, "/v1/admin/upstream-proxies/corp", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := proxyRequest(t, srv, tc.method, tc.path, memberToken, tc.body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s by a member = %d, want %d: %s", tc.method, tc.path, rec.Code, http.StatusForbidden, rec.Body.String())
			}
		})
	}

	// A member must not even learn that a profile exists.
	rec := proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies", memberToken, "")
	if strings.Contains(rec.Body.String(), "proxy.internal") {
		t.Fatalf("member response leaked proxy details: %s", rec.Body.String())
	}
}

func TestUpstreamProxyEndpointsRejectAnonymous(t *testing.T) {
	srv := newTestServer(withStore(newMockStore()))
	rec := proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies", "", "")
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous list = %d, want 401/403: %s", rec.Code, rec.Body.String())
	}
}

func TestUpstreamProxyCreateRejectsBadInput(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	cases := []struct {
		name string
		body string
	}{
		{"missing name", `{"scheme":"http","host":"proxy.internal:3128","on_failure":"fail_closed"}`},
		{"empty name", `{"name":"  ","scheme":"http","host":"proxy.internal:3128","on_failure":"fail_closed"}`},
		{"name too long", `{"name":"` + strings.Repeat("a", 65) + `","scheme":"http","host":"proxy.internal:3128","on_failure":"fail_closed"}`},
		{"unknown scheme", `{"name":"p","scheme":"ftp","host":"proxy.internal:21","on_failure":"fail_closed"}`},
		{"missing scheme", `{"name":"p","host":"proxy.internal:3128","on_failure":"fail_closed"}`},
		{"host without port", `{"name":"p","scheme":"http","host":"proxy.internal","on_failure":"fail_closed"}`},
		{"empty host", `{"name":"p","scheme":"http","host":"","on_failure":"fail_closed"}`},
		{"non-numeric port", `{"name":"p","scheme":"http","host":"proxy.internal:http","on_failure":"fail_closed"}`},
		{"host with userinfo", `{"name":"p","scheme":"http","host":"user:pass@proxy.internal:3128","on_failure":"fail_closed"}`},
		{"host with path", `{"name":"p","scheme":"http","host":"proxy.internal:3128/relay","on_failure":"fail_closed"}`},
		{"unknown failure policy", `{"name":"p","scheme":"http","host":"proxy.internal:3128","on_failure":"retry"}`},
		{"invalid json", `{"name":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("create(%s) = %d, want 400: %s", tc.body, rec.Code, rec.Body.String())
			}
		})
	}
	if len(ms.upstreamProxies) != 0 {
		t.Fatalf("expected no profiles persisted after %d rejected creates", len(ms.upstreamProxies))
	}
}

func TestUpstreamProxyAcceptsEverySupportedScheme(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		body := `{"name":"` + scheme + `-proxy","scheme":"` + scheme + `","host":"proxy.internal:3128","on_failure":"fail_closed"}`
		rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create scheme %s = %d, want 201: %s", scheme, rec.Code, rec.Body.String())
		}
	}
	rec := proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies", ownerToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Proxies []proxyView `json:"proxies"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listed.Proxies) != 4 {
		t.Fatalf("listed %d proxies, want 4", len(listed.Proxies))
	}
}

func TestUpstreamProxyCredentialsAreEncryptedAndNeverReturned(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"name":"corp","scheme":"http","host":"proxy.internal:3128","username":"svc-egress","password":"hunter2","on_failure":"fail_closed"}`
	rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	created := decodeProxyView(t, rec)

	if created.HasAuth != true {
		t.Fatal("has_auth = false, want true when credentials are set")
	}
	if created.Username != "svc-egress" {
		t.Fatalf("username = %q, want svc-egress", created.Username)
	}

	raw := rec.Body.String()
	for _, secret := range []string{"hunter2", "svc-egress"} {
		if _, ok := map[string]bool{"svc-egress": true}[secret]; ok {
			continue // the username is operator-readable by design
		}
		if strings.Contains(raw, secret) {
			t.Fatalf("create response leaked %q: %s", secret, raw)
		}
	}

	stored := ms.upstreamProxies["corp"]
	if len(stored.PasswordCT) == 0 || len(stored.PasswordNonce) == 0 {
		t.Fatal("password must be stored encrypted")
	}
	if strings.Contains(string(stored.PasswordCT), "hunter2") {
		t.Fatal("password ciphertext contains the plaintext")
	}

	// The list and read views must not carry the password either.
	assertNoPasswordField(t)
	rec = proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies", ownerToken, "")
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("list leaked the password: %s", rec.Body.String())
	}
}

// assertNoPasswordField guards the wire shape: reintroducing a password field
// to the view fails here rather than leaking at call time.
func assertNoPasswordField(t *testing.T) {
	t.Helper()
	typ := reflect.TypeOf(proxyView{})
	for i := 0; i < typ.NumField(); i++ {
		if strings.Contains(strings.ToLower(typ.Field(i).Tag.Get("json")), "password") {
			t.Fatalf("proxyView carries a password-bearing field %q; proxy secrets must stay write-only", typ.Field(i).Name)
		}
	}
}

func TestUpstreamProxyRotationKeepsUsernameWhenOnlyPasswordChanges(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken,
		`{"name":"corp","scheme":"http","host":"proxy.internal:3128","username":"svc-egress","password":"old","on_failure":"fail_closed"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}

	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken, `{"password":"new"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate = %d: %s", rec.Code, rec.Body.String())
	}
	rotated := decodeProxyView(t, rec)
	if rotated.Username != "svc-egress" {
		t.Fatalf("username after password-only rotation = %q, want it preserved", rotated.Username)
	}
	if !rotated.HasAuth {
		t.Fatal("has_auth must stay true after rotation")
	}

	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken, `{"clear_auth":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear = %d: %s", rec.Code, rec.Body.String())
	}
	cleared := decodeProxyView(t, rec)
	if cleared.HasAuth {
		t.Fatal("has_auth = true after clear_auth, want false")
	}
	if cleared.Username != "" {
		t.Fatalf("username = %q after clear_auth, want empty", cleared.Username)
	}
}

func TestUpstreamProxyUpdateRejectsBadInput(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken,
		`{"name":"corp","scheme":"http","host":"proxy.internal:3128","on_failure":"fail_closed"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}

	for _, tc := range []struct{ name, body string }{
		{"bad scheme", `{"scheme":"gopher"}`},
		{"bad host", `{"host":"proxy.internal"}`},
		{"bad failure policy", `{"on_failure":"sometimes"}`},
		{"invalid json", `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("patch(%s) = %d, want 400: %s", tc.body, rec.Code, rec.Body.String())
			}
		})
	}

	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/absent", ownerToken, `{"host":"h:1"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("patch missing = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

func TestUpstreamProxyDefaultIsExclusive(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	for _, body := range []string{
		`{"name":"first","scheme":"http","host":"a.internal:3128","on_failure":"fail_closed","is_default":true}`,
		`{"name":"second","scheme":"http","host":"b.internal:3128","on_failure":"fail_closed","is_default":true}`,
	} {
		if rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken, body); rec.Code != http.StatusCreated {
			t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
		}
	}

	var defaults int
	for _, p := range ms.upstreamProxies {
		if p.IsDefault {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatalf("%d profiles flagged default, want exactly 1 (is_default is exclusive)", defaults)
	}

	// Promoting an existing profile must demote the previous holder.
	if rec := proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/first", ownerToken, `{"is_default":true}`); rec.Code != http.StatusOK {
		t.Fatalf("promote = %d: %s", rec.Code, rec.Body.String())
	}
	defaults = 0
	for _, p := range ms.upstreamProxies {
		if p.IsDefault {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatalf("%d profiles flagged default after promotion, want 1", defaults)
	}
}

func TestUpstreamProxyDuplicateNameIsConflict(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"name":"corp","scheme":"http","host":"a.internal:3128","on_failure":"fail_closed"}`
	if rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken, body); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create = %d, want 409: %s", rec.Code, rec.Body.String())
	}
}

func TestUpstreamProxyDeleteRefusedWhileReferenced(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	if rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken,
		`{"name":"corp","scheme":"http","host":"a.internal:3128","on_failure":"fail_closed"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	ms.upstreamProxyRefs["corp"] = []string{"default/anthropic", "team/openai"}

	rec := proxyRequest(t, srv, http.MethodDelete, "/v1/admin/upstream-proxies/corp", ownerToken, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete referenced = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "anthropic") {
		t.Fatalf("409 must name the referencing services: %s", rec.Body.String())
	}
	if _, ok := ms.upstreamProxies["corp"]; !ok {
		t.Fatal("referenced profile must survive the refused delete")
	}

	delete(ms.upstreamProxyRefs, "corp")
	rec = proxyRequest(t, srv, http.MethodDelete, "/v1/admin/upstream-proxies/corp", ownerToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := ms.upstreamProxies["corp"]; ok {
		t.Fatal("profile remained after delete")
	}
}

// TestServiceUpstreamProxyReferenceRoundTrip covers the *consumer* side of the
// profile API: a service references a profile by name through the normal
// vault write path, and a reference to a profile that does not exist is
// rejected before it can be persisted. A half-written reference would leave a
// service whose traffic silently falls back to a direct dial.
func TestServiceUpstreamProxyReferenceRoundTrip(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	if rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken,
		`{"name":"corp","scheme":"http","host":"a.internal:3128","on_failure":"fail_closed"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create proxy = %d: %s", rec.Code, rec.Body.String())
	}

	put := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/v1/vaults/default/services", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+ownerToken)
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, r)
		return rec
	}

	const service = `{"name":"anthropic","host":"api.anthropic.com","auth":{"type":"bearer","token":"ANTHROPIC_KEY"},"upstream_proxy":"%s"}`
	if rec := put(fmt.Sprintf(`{"services":[%s]}`, fmt.Sprintf(service, "corp"))); rec.Code != http.StatusOK {
		t.Fatalf("PUT with valid reference = %d: %s", rec.Code, rec.Body.String())
	}

	// The reference must survive the read/write cycle, otherwise the UI would
	// present a selector that forgets the operator's choice on the next save.
	getRec := proxyRequest(t, srv, http.MethodGet, "/v1/vaults/default/services", ownerToken, "")
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET services = %d: %s", getRec.Code, getRec.Body.String())
	}
	var got struct {
		Services []struct {
			Name          string `json:"name"`
			UpstreamProxy string `json:"upstream_proxy"`
		} `json:"services"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&got); err != nil {
		t.Fatalf("decode services: %v", err)
	}
	if len(got.Services) != 1 || got.Services[0].UpstreamProxy != "corp" {
		t.Fatalf("upstream_proxy not persisted: %+v", got.Services)
	}

	rec := put(fmt.Sprintf(`{"services":[%s]}`, fmt.Sprintf(service, "no-such-proxy")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with unknown reference = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no-such-proxy") {
		t.Fatalf("400 must name the unknown profile: %s", rec.Body.String())
	}
}

func TestUpstreamProxyGetMissingIsNotFound(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	rec := proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies/absent", ownerToken, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}
