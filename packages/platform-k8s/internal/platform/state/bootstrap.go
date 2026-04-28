package state

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	statepostgres "code-code.internal/platform-k8s/internal/platform/state/postgres"
)

// OpenPostgres opens the platform state store and applies required migrations.
func OpenPostgres(ctx context.Context, databaseURL string, applicationName string) (*pgxpool.Pool, error) {
	pool, err := statepostgres.Connect(ctx, databaseURL, applicationName)
	if err != nil {
		return nil, err
	}
	if err := statepostgres.Migrate(ctx, pool, Migrations); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate platform state postgres: %w", err)
	}
	return pool, nil
}
