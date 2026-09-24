package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
)

// --- Upstream proxies (egress profiles) ---
//
// Profiles are instance-scoped: an operator defines them once and services
// reference them by name. Passwords are stored encrypted by the caller with
// the data encryption key; this layer only ever moves ciphertext around.

const upstreamProxyColumns = `id, name, scheme, host, username_ct, username_nonce, password_ct, password_nonce,
	no_proxy, proxy_ca_pem, on_failure, is_default, enabled, created_at, updated_at`

func (s *SQLStore) ListUpstreamProxies(ctx context.Context) ([]UpstreamProxy, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+upstreamProxyColumns+" FROM upstream_proxies ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("listing upstream proxies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []UpstreamProxy
	for rows.Next() {
		p, err := s.scanUpstreamProxy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetUpstreamProxyByName(ctx context.Context, name string) (*UpstreamProxy, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT "+upstreamProxyColumns+" FROM upstream_proxies WHERE name = ?"), name)
	p, err := s.scanUpstreamProxy(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("getting upstream proxy %q: %w", name, err)
	}
	return p, nil
}

// GetDefaultUpstreamProxy returns the instance-level fallback profile, or
// sql.ErrNoRows when none is marked default or the marked one is disabled.
func (s *SQLStore) GetDefaultUpstreamProxy(ctx context.Context) (*UpstreamProxy, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT "+upstreamProxyColumns+" FROM upstream_proxies WHERE is_default = ? AND enabled = ?",
		s.dialect.BoolVal(true), s.dialect.BoolVal(true))
	p, err := s.scanUpstreamProxy(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("getting default upstream proxy: %w", err)
	}
	return p, nil
}

func (s *SQLStore) CreateUpstreamProxy(ctx context.Context, p *UpstreamProxy) error {
	if p == nil || p.Name == "" {
		return fmt.Errorf("CreateUpstreamProxy: name is required")
	}
	if p.ID == "" {
		p.ID = newUUID()
	}
	now := s.now()

	// Only one profile can be the instance default; clear the previous one in
	// the same transaction so two defaults can never race into existence.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("CreateUpstreamProxy: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if p.IsDefault {
		if _, err := tx.ExecContext(ctx,
			s.dialect.Rebind("UPDATE upstream_proxies SET is_default = ?, updated_at = ? WHERE is_default = ?"),
			s.dialect.BoolVal(false), now, s.dialect.BoolVal(true)); err != nil {
			return fmt.Errorf("CreateUpstreamProxy: clearing previous default: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO upstream_proxies (
		id, name, scheme, host, username_ct, username_nonce, password_ct, password_nonce,
		no_proxy, proxy_ca_pem, on_failure, is_default, enabled, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		p.ID, p.Name, p.Scheme, p.Host, p.UsernameCT, p.UsernameNonce, p.PasswordCT, p.PasswordNonce,
		p.NoProxy, p.ProxyCAPEM, p.OnFailure, s.dialect.BoolVal(p.IsDefault), s.dialect.BoolVal(p.Enabled),
		now, now); err != nil {
		return fmt.Errorf("CreateUpstreamProxy: %w", err)
	}
	return tx.Commit()
}

func (s *SQLStore) UpdateUpstreamProxy(ctx context.Context, params UpdateUpstreamProxyParams) (*UpstreamProxy, error) {
	if params.Name == "" {
		return nil, fmt.Errorf("UpdateUpstreamProxy: name is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("UpdateUpstreamProxy: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	existing, err := s.getUpstreamProxyTx(ctx, tx, params.Name)
	if err != nil {
		return nil, err
	}

	var setClauses []string
	var args []interface{}
	add := func(column string, value interface{}) {
		setClauses = append(setClauses, column+" = ?")
		args = append(args, value)
	}

	if params.Scheme != nil {
		add("scheme", *params.Scheme)
	}
	if params.Host != nil {
		add("host", *params.Host)
	}
	if params.NoProxy != nil {
		add("no_proxy", *params.NoProxy)
	}
	if params.ProxyCAPEM != nil {
		add("proxy_ca_pem", *params.ProxyCAPEM)
	}
	if params.OnFailure != nil {
		add("on_failure", *params.OnFailure)
	}
	if params.Enabled != nil {
		add("enabled", s.dialect.BoolVal(*params.Enabled))
	}
	if params.UsernameCT != nil {
		add("username_ct", *params.UsernameCT)
	}
	if params.UsernameNonce != nil {
		add("username_nonce", *params.UsernameNonce)
	}
	if params.PasswordCT != nil {
		add("password_ct", *params.PasswordCT)
	}
	if params.PasswordNonce != nil {
		add("password_nonce", *params.PasswordNonce)
	}
	if params.IsDefault != nil {
		if *params.IsDefault {
			if _, err := tx.ExecContext(ctx,
				s.dialect.Rebind("UPDATE upstream_proxies SET is_default = ?, updated_at = ? WHERE is_default = ?"),
				s.dialect.BoolVal(false), s.now(), s.dialect.BoolVal(true)); err != nil {
				return nil, fmt.Errorf("UpdateUpstreamProxy: clearing previous default: %w", err)
			}
		}
		add("is_default", s.dialect.BoolVal(*params.IsDefault))
	}

	if len(setClauses) == 0 {
		return existing, tx.Commit()
	}

	setClauses = append(setClauses, "updated_at = ?")
	args = append(args, s.now())
	args = append(args, params.Name)

	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind("UPDATE upstream_proxies SET "+strings.Join(setClauses, ", ")+" WHERE name = ?"),
		args...); err != nil {
		return nil, fmt.Errorf("UpdateUpstreamProxy: %w", err)
	}

	updated, err := s.getUpstreamProxyTx(ctx, tx, params.Name)
	if err != nil {
		return nil, err
	}
	return updated, tx.Commit()
}

func (s *SQLStore) DeleteUpstreamProxy(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("DELETE FROM upstream_proxies WHERE name = ?"), name)
	if err != nil {
		return fmt.Errorf("DeleteUpstreamProxy: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("DeleteUpstreamProxy: rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CountUpstreamProxyReferences scans every vault's broker config for services
// pointing at the named profile and returns "<vault>/<service>" strings. Agent
// Vault stores services as JSON, so this is a scan by necessity — profiles are
// few and the check happens only on delete.
func (s *SQLStore) CountUpstreamProxyReferences(ctx context.Context, name string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT bc.vault_id, v.name, bc.services_json FROM broker_configs bc JOIN vaults v ON v.id = bc.vault_id")
	if err != nil {
		return nil, fmt.Errorf("counting upstream proxy references: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var refs []string
	for rows.Next() {
		var vaultID, vaultName, servicesJSON string
		if err := rows.Scan(&vaultID, &vaultName, &servicesJSON); err != nil {
			return nil, fmt.Errorf("scanning broker config: %w", err)
		}
		var services []broker.Service
		if err := json.Unmarshal([]byte(servicesJSON), &services); err != nil {
			continue
		}
		for _, svc := range services {
			if strings.EqualFold(svc.UpstreamProxy, name) {
				refs = append(refs, fmt.Sprintf("%s/%s", vaultName, svc.Name))
			}
		}
	}
	return refs, rows.Err()
}

func (s *SQLStore) getUpstreamProxyTx(ctx context.Context, tx *sql.Tx, name string) (*UpstreamProxy, error) {
	row := tx.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT "+upstreamProxyColumns+" FROM upstream_proxies WHERE name = ?"), name)
	p, err := s.scanUpstreamProxy(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("getting upstream proxy %q: %w", name, err)
	}
	return p, nil
}

type sqlScanner interface {
	Scan(dest ...interface{}) error
}

func (s *SQLStore) scanUpstreamProxy(row sqlScanner) (*UpstreamProxy, error) {
	var p UpstreamProxy
	var createdAt, updatedAt interface{}
	if err := row.Scan(
		&p.ID, &p.Name, &p.Scheme, &p.Host,
		&p.UsernameCT, &p.UsernameNonce, &p.PasswordCT, &p.PasswordNonce,
		&p.NoProxy, &p.ProxyCAPEM, &p.OnFailure, &p.IsDefault, &p.Enabled,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	// SQLite stores booleans as integers and Postgres as BOOLEAN; scanning into
	// bool works for both with their respective drivers.
	p.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	p.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	return &p, nil
}
