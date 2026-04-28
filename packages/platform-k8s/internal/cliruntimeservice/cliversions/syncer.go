package cliversions

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
	clisupport "code-code.internal/platform-k8s/internal/supportservice/clidefinitions/support"
)

type Syncer struct {
	store      Store
	cliSupport CLISupportLister
	fetcher    *Fetcher
	now        func() time.Time
	logger     *slog.Logger
}

type CLISupportLister interface {
	List(context.Context) ([]*supportv1.CLI, error)
}

type SyncerConfig struct {
	Store      Store
	CLISupport CLISupportLister
	Fetcher    *Fetcher
	Now        func() time.Time
	Logger     *slog.Logger
}

type SyncResult struct {
	Changes []VersionChange
}

type VersionChange struct {
	CLIID    string
	Previous Snapshot
	Current  Snapshot
}

func NewSyncer(config SyncerConfig) (*Syncer, error) {
	if config.Store == nil {
		return nil, fmt.Errorf("platformk8s/cliversions: store is nil")
	}
	if config.Fetcher == nil {
		config.Fetcher = NewFetcherWithHTTPClientFactory(outboundhttp.NewClientFactory())
	}
	if config.CLISupport == nil {
		config.CLISupport = staticCLISupportLister{}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Syncer{
		store:      config.Store,
		cliSupport: config.CLISupport,
		fetcher:    config.Fetcher,
		now:        config.Now,
		logger:     config.Logger,
	}, nil
}

func (s *Syncer) Sync(ctx context.Context) (*SyncResult, error) {
	current, err := s.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	next := newState()
	for cliID, snapshot := range current.Versions {
		next.Versions[cliID] = snapshot
	}
	clis, err := s.cliSupport.List(ctx)
	if err != nil {
		return nil, err
	}
	configured := map[string]struct{}{}
	var errs []error
	result := &SyncResult{}
	for _, cli := range clis {
		source, ok, sourceErr := ResolveSource(cli)
		if sourceErr != nil {
			errs = append(errs, sourceErr)
			continue
		}
		cliID := strings.TrimSpace(cli.GetCliId())
		if cliID == "" {
			continue
		}
		if !ok {
			delete(next.Versions, cliID)
			continue
		}
		configured[cliID] = struct{}{}
		version, fetchErr := s.fetcher.Fetch(ctx, source)
		if fetchErr != nil {
			errs = append(errs, fetchErr)
			continue
		}
		previous, hadPrevious := current.Versions[cliID]
		if hadPrevious && previous.Version == version {
			next.Versions[cliID] = previous
			continue
		}
		currentSnapshot := Snapshot{
			Version:   version,
			UpdatedAt: s.now().UTC(),
		}
		next.Versions[cliID] = currentSnapshot
		result.Changes = append(result.Changes, VersionChange{
			CLIID:    cliID,
			Previous: previous,
			Current:  currentSnapshot,
		})
	}
	for cliID := range next.Versions {
		if _, ok := configured[cliID]; !ok {
			delete(next.Versions, cliID)
		}
	}
	if !reflect.DeepEqual(current, next) {
		if err := s.store.Save(ctx, next); err != nil {
			return nil, err
		}
	}
	return result, errors.Join(errs...)
}

type staticCLISupportLister struct{}

func (staticCLISupportLister) List(context.Context) ([]*supportv1.CLI, error) {
	return clisupport.RegisteredCLIs()
}
