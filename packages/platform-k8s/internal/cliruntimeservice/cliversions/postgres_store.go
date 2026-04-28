package cliversions

import (
	"context"
	"fmt"
	"strings"
	"time"

	cliruntimev1 "code-code.internal/go-contract/platform/cli_runtime/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	statepostgres "code-code.internal/platform-k8s/internal/platform/state/postgres"
)

const postgresVersionSnapshotTable = "platform_cli_version_snapshots"

type PostgresStore struct {
	repository *statepostgres.JSONRepository
}

func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	repository, err := statepostgres.NewJSONRepository(pool, postgresVersionSnapshotTable)
	if err != nil {
		return nil, err
	}
	return &PostgresStore{repository: repository}, nil
}

func (s *PostgresStore) Load(ctx context.Context) (*State, error) {
	if s == nil || s.repository == nil {
		return nil, fmt.Errorf("platformk8s/cliversions: postgres store is nil")
	}
	records, err := s.repository.List(ctx)
	if err != nil {
		return nil, err
	}
	state := newState()
	for _, row := range records {
		record := &cliruntimev1.CLIVersionSnapshot{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(row.Payload, record); err != nil {
			return nil, fmt.Errorf("platformk8s/cliversions: decode version snapshot %q: %w", row.ID, err)
		}
		cliID := strings.TrimSpace(record.GetCliId())
		if cliID == "" {
			cliID = strings.TrimSpace(row.ID)
		}
		if cliID == "" || strings.TrimSpace(record.GetVersion()) == "" {
			continue
		}
		updatedAt := time.Time{}
		if record.GetUpdatedAt() != nil {
			updatedAt = record.GetUpdatedAt().AsTime()
		}
		state.Versions[cliID] = Snapshot{
			Version:   strings.TrimSpace(record.GetVersion()),
			UpdatedAt: updatedAt,
		}
	}
	return state, nil
}

func (s *PostgresStore) Save(ctx context.Context, state *State) error {
	if s == nil || s.repository == nil {
		return fmt.Errorf("platformk8s/cliversions: postgres store is nil")
	}
	if state == nil {
		state = newState()
	}
	for cliID, snapshot := range state.Versions {
		cliID = strings.TrimSpace(cliID)
		if cliID == "" || strings.TrimSpace(snapshot.Version) == "" {
			continue
		}
		payload, err := (protojson.MarshalOptions{}).Marshal(&cliruntimev1.CLIVersionSnapshot{
			CliId:     cliID,
			Version:   strings.TrimSpace(snapshot.Version),
			UpdatedAt: timestamppb.New(snapshot.UpdatedAt),
		})
		if err != nil {
			return fmt.Errorf("platformk8s/cliversions: encode version snapshot %q: %w", cliID, err)
		}
		if err := s.repository.Put(ctx, cliID, payload); err != nil {
			return err
		}
	}
	return s.deleteStale(ctx, state)
}

func (s *PostgresStore) deleteStale(ctx context.Context, state *State) error {
	records, err := s.repository.List(ctx)
	if err != nil {
		return err
	}
	for _, row := range records {
		if _, ok := state.Versions[row.ID]; ok {
			continue
		}
		if err := s.repository.Delete(ctx, row.ID); err != nil {
			return err
		}
	}
	return nil
}
