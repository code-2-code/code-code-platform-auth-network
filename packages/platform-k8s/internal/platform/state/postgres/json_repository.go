package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5/pgxpool"
)

// JSONRepository stores domain-owned protobuf JSON snapshots in one table.
type JSONRepository struct {
	pool  *pgxpool.Pool
	table string
}

// JSONRecord is one persisted JSON state row.
type JSONRecord struct {
	ID         string
	Payload    []byte
	Generation int64
}

// NewJSONRepository creates a repository for an already-migrated JSONB table.
func NewJSONRepository(pool *pgxpool.Pool, table string) (*JSONRepository, error) {
	table = strings.TrimSpace(table)
	if pool == nil {
		return nil, fmt.Errorf("platform state postgres pool is nil")
	}
	if !safeIdentifier(table) {
		return nil, fmt.Errorf("platform state postgres table %q is invalid", table)
	}
	return &JSONRepository{pool: pool, table: table}, nil
}

func (r *JSONRepository) Put(ctx context.Context, id string, payload []byte) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("platform state postgres id is empty")
	}
	if !json.Valid(payload) {
		return fmt.Errorf("platform state postgres payload for %q is not valid json", id)
	}
	_, err := r.pool.Exec(ctx, fmt.Sprintf(`
insert into %s (id, payload, generation, created_at, updated_at)
values ($1, $2::jsonb, 1, now(), now())
on conflict (id) do update
set payload = excluded.payload,
    generation = %s.generation + 1,
    updated_at = now()`, r.table, r.table), id, string(payload))
	if err != nil {
		return fmt.Errorf("put platform state %s/%s: %w", r.table, id, err)
	}
	return nil
}

func (r *JSONRepository) Insert(ctx context.Context, id string, payload []byte) (int64, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return 0, fmt.Errorf("platform state postgres id is empty")
	}
	if !json.Valid(payload) {
		return 0, fmt.Errorf("platform state postgres payload for %q is not valid json", id)
	}
	var generation int64
	err := r.pool.QueryRow(ctx, fmt.Sprintf(`
insert into %s (id, payload, generation, created_at, updated_at)
values ($1, $2::jsonb, 1, now(), now())
on conflict (id) do nothing
returning generation`, r.table), id, string(payload)).Scan(&generation)
	if err != nil {
		return 0, fmt.Errorf("insert platform state %s/%s: %w", r.table, id, err)
	}
	return generation, nil
}

func (r *JSONRepository) Update(ctx context.Context, id string, payload []byte) (int64, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return 0, fmt.Errorf("platform state postgres id is empty")
	}
	if !json.Valid(payload) {
		return 0, fmt.Errorf("platform state postgres payload for %q is not valid json", id)
	}
	var generation int64
	err := r.pool.QueryRow(ctx, fmt.Sprintf(`
update %s
set payload = $2::jsonb,
    generation = generation + 1,
    updated_at = now()
where id = $1
returning generation`, r.table), id, string(payload)).Scan(&generation)
	if err != nil {
		return 0, fmt.Errorf("update platform state %s/%s: %w", r.table, id, err)
	}
	return generation, nil
}

func (r *JSONRepository) Get(ctx context.Context, id string) ([]byte, int64, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, 0, fmt.Errorf("platform state postgres id is empty")
	}
	var raw []byte
	var generation int64
	err := r.pool.QueryRow(ctx, fmt.Sprintf("select payload, generation from %s where id = $1", r.table), id).Scan(&raw, &generation)
	if err != nil {
		return nil, 0, fmt.Errorf("get platform state %s/%s: %w", r.table, id, err)
	}
	return raw, generation, nil
}

func (r *JSONRepository) List(ctx context.Context) ([]JSONRecord, error) {
	rows, err := r.pool.Query(ctx, fmt.Sprintf("select id, payload, generation from %s order by id", r.table))
	if err != nil {
		return nil, fmt.Errorf("list platform state %s: %w", r.table, err)
	}
	defer rows.Close()

	records := []JSONRecord{}
	for rows.Next() {
		var record JSONRecord
		if err := rows.Scan(&record.ID, &record.Payload, &record.Generation); err != nil {
			return nil, fmt.Errorf("scan platform state %s: %w", r.table, err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate platform state %s: %w", r.table, err)
	}
	return records, nil
}

func (r *JSONRepository) Delete(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("platform state postgres id is empty")
	}
	if _, err := r.pool.Exec(ctx, fmt.Sprintf("delete from %s where id = $1", r.table), id); err != nil {
		return fmt.Errorf("delete platform state %s/%s: %w", r.table, id, err)
	}
	return nil
}

func safeIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for index, r := range value {
		if r == '_' || unicode.IsLetter(r) || index > 0 && unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}
