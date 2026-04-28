package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationLockID int64 = 948513204

// Migration is one idempotent platform-state schema step.
type Migration struct {
	Version int64
	Name    string
	SQL     string
}

// Migrate applies migrations once, guarded by a Postgres advisory lock.
func Migrate(ctx context.Context, pool *pgxpool.Pool, migrations []Migration) error {
	if pool == nil {
		return fmt.Errorf("platform state postgres pool is nil")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin platform state migration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("lock platform state migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `
create table if not exists platform_schema_migrations (
	version bigint primary key,
	name text not null,
	applied_at timestamptz not null default now()
)`); err != nil {
		return fmt.Errorf("ensure platform_schema_migrations: %w", err)
	}
	for _, migration := range migrations {
		if err := validateMigration(migration); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, "select exists(select 1 from platform_schema_migrations where version = $1)", migration.Version).Scan(&exists); err != nil {
			return fmt.Errorf("read platform state migration %d: %w", migration.Version, err)
		}
		if exists {
			continue
		}
		if _, err := tx.Exec(ctx, migration.SQL); err != nil {
			return fmt.Errorf("apply platform state migration %d %s: %w", migration.Version, migration.Name, err)
		}
		if _, err := tx.Exec(ctx, "insert into platform_schema_migrations(version, name) values($1, $2)", migration.Version, migration.Name); err != nil {
			return fmt.Errorf("record platform state migration %d: %w", migration.Version, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit platform state migration: %w", err)
	}
	return nil
}

func validateMigration(migration Migration) error {
	if migration.Version <= 0 {
		return fmt.Errorf("platform state migration version must be positive")
	}
	if strings.TrimSpace(migration.Name) == "" {
		return fmt.Errorf("platform state migration %d name is empty", migration.Version)
	}
	if strings.TrimSpace(migration.SQL) == "" {
		return fmt.Errorf("platform state migration %d sql is empty", migration.Version)
	}
	return nil
}
