package store

import (
	"fmt"

	"gorm.io/gorm"
)

// M1: enforce the "at most one instance-level default upstream proxy"
// invariant at the database level. The application-side clear-then-set
// sequence is fine for SQLite (single writer due to SetMaxOpenConns(1)) but
// on Postgres two concurrent "make this the default" updates can both clear
// then both set, leaving two rows marked default. A partial unique index
// makes the second write fail instead of silently corrupting the invariant.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		var n int64
		if err := db.Table("upstream_proxies").
			Where("is_default = ?", true).Count(&n).Error; err != nil {
			return err
		}
		if n > 1 {
			// Refuse to silently paper over a dataset that already violates
			// the invariant; surface it so an operator consolidates first.
			// This intentionally blocks startup rather than silently allowing
			// more than one default, so the operator must fix the data.
			return fmt.Errorf(
				"upstream_proxies has %d default profiles; only one is allowed. "+
					"Fix before restarting, e.g. keep the intended default and clear the rest: "+
					"UPDATE upstream_proxies SET is_default = false WHERE name NOT IN (<your intended default name>); "+
					"then re-run migration 20261012000000", n)
		}
		if db.Name() == "postgres" {
			return db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS upstream_proxies_single_default
				ON upstream_proxies (is_default) WHERE is_default`).Error
		}
		return db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS upstream_proxies_single_default
			ON upstream_proxies (is_default) WHERE is_default = 1`).Error
	})
}
