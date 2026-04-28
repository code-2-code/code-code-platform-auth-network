package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect opens one bounded Postgres connection pool for platform state.
func Connect(ctx context.Context, databaseURL string, applicationName string) (*pgxpool.Pool, error) {
	databaseURL = strings.TrimSpace(databaseURL)
	if databaseURL == "" {
		return nil, fmt.Errorf("platform state postgres database url is empty")
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse platform state postgres database url: %w", err)
	}
	if strings.TrimSpace(applicationName) != "" {
		config.ConnConfig.RuntimeParams["application_name"] = strings.TrimSpace(applicationName)
	}
	if config.MaxConns == 0 {
		config.MaxConns = 8
	}
	config.MinConns = 0
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open platform state postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping platform state postgres: %w", err)
	}
	return pool, nil
}
