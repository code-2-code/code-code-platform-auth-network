package cliversions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
)

func TestSyncerSyncAllPersistsFetchedVersions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/package/@openai/codex/dist-tags":
			_, _ = w.Write([]byte(`{"latest":"0.121.0"}`))
		case "/-/package/@anthropic-ai/claude-code/dist-tags":
			_, _ = w.Write([]byte(`{"latest":"2.0.0"}`))
		case "/-/package/@google/gemini-cli/dist-tags":
			_, _ = w.Write([]byte(`{"latest":"0.9.0"}`))
		case "/antigravity.json":
			_, _ = w.Write([]byte(`{"version":"1.22.2,5206900187463680"}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	now := time.Unix(1713480000, 0).UTC()
	store := newMemoryStore()

	syncer, err := NewSyncer(SyncerConfig{
		Store: store,
		Fetcher: func() *Fetcher {
			fetcher := NewFetcher(server.Client())
			fetcher.npmBaseURL = server.URL
			fetcher.homebrewBaseURL = server.URL
			return fetcher
		}(),
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSyncer() error = %v", err)
	}
	result, err := syncer.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got, want := len(result.Changes), 4; got != want {
		t.Fatalf("changes = %d, want %d", got, want)
	}

	state, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	if got, want := state.Versions["codex"].Version, "0.121.0"; got != want {
		t.Fatalf("codex version = %q, want %q", got, want)
	}
	if got, want := state.Versions["antigravity"].Version, "1.22.2"; got != want {
		t.Fatalf("antigravity version = %q, want %q", got, want)
	}
	if got, want := state.Versions["claude-code"].Version, "2.0.0"; got != want {
		t.Fatalf("claude-code version = %q, want %q", got, want)
	}
	if got, want := state.Versions["gemini-cli"].Version, "0.9.0"; got != want {
		t.Fatalf("gemini-cli version = %q, want %q", got, want)
	}
}

func TestSyncerSyncAllKeepsPreviousSnapshotOnFetchFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer server.Close()

	store := newMemoryStore()
	store.state.Versions["codex"] = Snapshot{Version: "0.120.0"}

	syncer, err := NewSyncer(SyncerConfig{
		Store: store,
		Fetcher: func() *Fetcher {
			fetcher := NewFetcher(server.Client())
			fetcher.npmBaseURL = server.URL
			return fetcher
		}(),
	})
	if err != nil {
		t.Fatalf("NewSyncer() error = %v", err)
	}
	if _, err := syncer.Sync(context.Background()); err == nil {
		t.Fatal("Sync() error = nil, want error")
	}

	state, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	if got, want := state.Versions["codex"].Version, "0.120.0"; got != want {
		t.Fatalf("codex version = %q, want %q", got, want)
	}
}

func TestSyncerSyncReadsCLISupportAndStateFromStore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/package/@openai/codex/dist-tags":
			_, _ = w.Write([]byte(`{"latest":"0.121.0"}`))
		case "/-/package/@anthropic-ai/claude-code/dist-tags":
			_, _ = w.Write([]byte(`{"latest":"2.0.0"}`))
		case "/-/package/@google/gemini-cli/dist-tags":
			_, _ = w.Write([]byte(`{"latest":"0.9.0"}`))
		case "/antigravity.json":
			_, _ = w.Write([]byte(`{"version":"1.22.2,5206900187463680"}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	store := newMemoryStore()
	store.state.Versions["codex"] = Snapshot{Version: "0.120.0"}

	syncer, err := NewSyncer(SyncerConfig{
		Store: store,
		Fetcher: func() *Fetcher {
			fetcher := NewFetcher(server.Client())
			fetcher.npmBaseURL = server.URL
			fetcher.homebrewBaseURL = server.URL
			return fetcher
		}(),
	})
	if err != nil {
		t.Fatalf("NewSyncer() error = %v", err)
	}
	result, err := syncer.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got, want := len(result.Changes), 4; got != want {
		t.Fatalf("changes = %d, want %d", got, want)
	}

	state, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	if got, want := state.Versions["codex"].Version, "0.121.0"; got != want {
		t.Fatalf("codex version = %q, want %q", got, want)
	}
}

func TestNewSyncerUsesPlatformOutboundHTTPClientByDefault(t *testing.T) {
	store := newMemoryStore()

	syncer, err := NewSyncer(SyncerConfig{
		Store: store,
	})
	if err != nil {
		t.Fatalf("NewSyncer() error = %v", err)
	}
	if _, ok := syncer.fetcher.clientFactory.(outboundhttp.ClientFactory); !ok {
		t.Fatalf("clientFactory = %T, want outboundhttp.ClientFactory", syncer.fetcher.clientFactory)
	}
}

func TestSyncerSyncPreservesSnapshotWhenVersionDoesNotChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/package/@openai/codex/dist-tags":
			_, _ = w.Write([]byte(`{"latest":"0.120.0"}`))
		case "/-/package/@anthropic-ai/claude-code/dist-tags":
			_, _ = w.Write([]byte(`{"latest":"2.0.0"}`))
		case "/-/package/@google/gemini-cli/dist-tags":
			_, _ = w.Write([]byte(`{"latest":"0.9.0"}`))
		case "/antigravity.json":
			_, _ = w.Write([]byte(`{"version":"1.22.2,5206900187463680"}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	previousUpdatedAt := time.Date(2024, 4, 13, 8, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	store.state.Versions["codex"] = Snapshot{Version: "0.120.0", UpdatedAt: previousUpdatedAt}

	syncer, err := NewSyncer(SyncerConfig{
		Store: store,
		Fetcher: func() *Fetcher {
			fetcher := NewFetcher(server.Client())
			fetcher.npmBaseURL = server.URL
			fetcher.homebrewBaseURL = server.URL
			return fetcher
		}(),
	})
	if err != nil {
		t.Fatalf("NewSyncer() error = %v", err)
	}
	result, err := syncer.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	for _, change := range result.Changes {
		if change.CLIID == "codex" {
			t.Fatalf("codex produced change for unchanged version: %+v", change)
		}
	}

	state, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	if got := state.Versions["codex"].UpdatedAt; !got.Equal(previousUpdatedAt) {
		t.Fatalf("codex updatedAt = %s, want %s", got, previousUpdatedAt)
	}
}

type memoryStore struct {
	state *State
}

func newMemoryStore() *memoryStore {
	return &memoryStore{state: newState()}
}

func (s *memoryStore) Load(context.Context) (*State, error) {
	return s.state.clone(), nil
}

func (s *memoryStore) Save(_ context.Context, state *State) error {
	s.state = state.clone()
	return nil
}
