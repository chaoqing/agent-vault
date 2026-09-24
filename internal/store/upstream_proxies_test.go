package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

// These exercise the real SQL paths rather than a mock, so the migration, the
// writer-oriented update semantics, and the reference scan across broker
// configs are all checked against the database they run on.

func insertProxy(t *testing.T, s *SQLStore, p *UpstreamProxy) *UpstreamProxy {
	t.Helper()
	if err := s.CreateUpstreamProxy(context.Background(), p); err != nil {
		t.Fatalf("CreateUpstreamProxy: %v", err)
	}
	return p
}

func TestUpstreamProxyMigrationCreatesTable(t *testing.T) {
	s := openTestDB(t)

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM upstream_proxies").Scan(&count); err != nil {
		t.Fatalf("upstream_proxies table missing after migration: %v", err)
	}

	// SQLite stores booleans as integers; the migration must pick the right
	// type for each dialect or every IsDefault read silently returns false.
	_, err := s.db.Exec(`INSERT INTO upstream_proxies
		(id, name, scheme, host, on_failure, is_default, enabled, created_at, updated_at)
		VALUES ('p1', 'p', 'http', 'proxy:3128', 'fail_closed', 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatalf("inserting an upstream_proxy row: %v", err)
	}
}

func TestUpstreamProxyCRUDAgainstSQLite(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	insertProxy(t, s, &UpstreamProxy{
		Name: "corp", Scheme: "http", Host: "proxy.internal:3128",
		NoProxy: "example.com", ProxyCAPEM: "-----BEGIN CERTIFICATE-----",
		OnFailure: "fail_closed", IsDefault: true, Enabled: true,
		UsernameCT: []byte("u"), UsernameNonce: []byte("un"),
		PasswordCT: []byte("p"), PasswordNonce: []byte("pn"),
	})

	listed, err := s.ListUpstreamProxies(ctx)
	if err != nil {
		t.Fatalf("ListUpstreamProxies: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed %d proxies, want 1", len(listed))
	}
	if listed[0].PasswordCT == nil {
		t.Fatal("ciphertext columns must round-trip as blobs")
	}

	byName, err := s.GetUpstreamProxyByName(ctx, "corp")
	if err != nil {
		t.Fatalf("GetUpstreamProxyByName: %v", err)
	}
	if byName.Host != "proxy.internal:3128" || byName.OnFailure != "fail_closed" || !byName.IsDefault {
		t.Fatalf("stored proxy = %+v, want the inserted values", byName)
	}

	def, err := s.GetDefaultUpstreamProxy(ctx)
	if err != nil {
		t.Fatalf("GetDefaultUpstreamProxy: %v", err)
	}
	if def.Name != "corp" {
		t.Fatalf("default = %q, want corp", def.Name)
	}

	if _, err := s.GetUpstreamProxyByName(ctx, "absent"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetUpstreamProxyByName(absent) = %v, want sql.ErrNoRows", err)
	}
}

func TestUpstreamProxyDuplicateCreateIsRejected(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	insertProxy(t, s, &UpstreamProxy{Name: "corp", Scheme: "http", Host: "a:3128", OnFailure: "fail_closed", Enabled: true})
	err := s.CreateUpstreamProxy(ctx, &UpstreamProxy{Name: "corp", Scheme: "http", Host: "b:3128", OnFailure: "fail_closed", Enabled: true})
	if err == nil {
		t.Fatal("duplicate names must be rejected by the unique index")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") {
		t.Fatalf("error = %v, want a UNIQUE violation", err)
	}
}

func TestUpstreamProxyDefaultIsExclusiveInSQLite(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	insertProxy(t, s, &UpstreamProxy{Name: "first", Scheme: "http", Host: "a:3128", OnFailure: "fail_closed", IsDefault: true, Enabled: true})
	insertProxy(t, s, &UpstreamProxy{Name: "second", Scheme: "http", Host: "b:3128", OnFailure: "fail_closed", IsDefault: true, Enabled: true})

	first, err := s.GetUpstreamProxyByName(ctx, "first")
	if err != nil {
		t.Fatalf("GetUpstreamProxyByName: %v", err)
	}
	if first.IsDefault {
		t.Fatal("promoting 'second' must demote 'first'; is_default is a single-valued pointer")
	}

	promote := true
	updated, err := s.UpdateUpstreamProxy(ctx, UpdateUpstreamProxyParams{Name: "first", IsDefault: &promote})
	if err != nil {
		t.Fatalf("UpdateUpstreamProxy: %v", err)
	}
	if !updated.IsDefault {
		t.Fatal("explicit promotion must take effect")
	}
	demoted, err := s.GetUpstreamProxyByName(ctx, "second")
	if err != nil {
		t.Fatalf("GetUpstreamProxyByName: %v", err)
	}
	if demoted.IsDefault {
		t.Fatal("previous default must be cleared on promotion")
	}
}

func TestUpstreamProxyPatchSemantics(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	insertProxy(t, s, &UpstreamProxy{
		Name: "corp", Scheme: "http", Host: "a:3128",
		NoProxy: "example.com", OnFailure: "fail_closed", Enabled: true,
		UsernameCT: []byte("u"), UsernameNonce: []byte("un"),
	})

	host := "renamed.internal:3129"
	noProxy := ""
	updated, err := s.UpdateUpstreamProxy(ctx, UpdateUpstreamProxyParams{Name: "corp", Host: &host, NoProxy: &noProxy})
	if err != nil {
		t.Fatalf("UpdateUpstreamProxy: %v", err)
	}
	if updated.Host != host {
		t.Fatalf("host = %q, want %q", updated.Host, host)
	}
	if updated.NoProxy != "" {
		t.Fatalf("no_proxy = %q, want an explicit non-nil pointer to clear it", updated.NoProxy)
	}
	// Untouched columns must survive a partial patch.
	if len(updated.UsernameCT) == 0 {
		t.Fatal("partial patch must not clear credentials it did not mention")
	}
	if updated.OnFailure != "fail_closed" {
		t.Fatalf("on_failure = %q, want unchanged", updated.OnFailure)
	}

	if _, err := s.UpdateUpstreamProxy(ctx, UpdateUpstreamProxyParams{Name: "absent", Host: &host}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("UpdateUpstreamProxy(absent) = %v, want sql.ErrNoRows", err)
	}
}

func TestUpstreamProxyDeleteRefusesWhenReferenced(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	insertProxy(t, s, &UpstreamProxy{Name: "corp", Scheme: "http", Host: "a:3128", OnFailure: "fail_closed", Enabled: true})

	refs, err := s.CountUpstreamProxyReferences(ctx, "corp")
	if err != nil {
		t.Fatalf("CountUpstreamProxyReferences: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("references = %v, want none for an unused profile", refs)
	}

	vault, err := s.CreateVault(ctx, "demo")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	services := `[{"name":"anthropic","host":"api.anthropic.com","auth":{"type":"bearer","token":"t"},"upstream_proxy":"corp"},` +
		`{"name":"openai","host":"api.openai.com","auth":{"type":"bearer","token":"t"}}]`
	if _, err := s.SetBrokerConfig(ctx, vault.ID, services); err != nil {
		t.Fatalf("seeding broker config: %v", err)
	}

	refs, err = s.CountUpstreamProxyReferences(ctx, "corp")
	if err != nil {
		t.Fatalf("CountUpstreamProxyReferences: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("references = %v, want exactly the anthropic service", refs)
	}
	// References are reported as vault name / service name — the form an
	// operator recognises from the UI, not raw IDs.
	if refs[0] != "demo/anthropic" {
		t.Fatalf("reference = %q, want demo/anthropic", refs[0])
	}

	if err := s.DeleteUpstreamProxy(ctx, "absent"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("DeleteUpstreamProxy(absent) = %v, want sql.ErrNoRows", err)
	}
	if err := s.DeleteUpstreamProxy(ctx, "corp"); err != nil {
		t.Fatalf("DeleteUpstreamProxy: %v", err)
	}
	if _, err := s.GetUpstreamProxyByName(ctx, "corp"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("proxy survived deletion: %v", err)
	}
}
