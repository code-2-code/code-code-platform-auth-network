package cliversions

import (
	"context"
	"testing"
)

func TestResolvePrefersSyncedVersionState(t *testing.T) {
	store := newMemoryStore()
	store.state.Versions["codex"] = Snapshot{Version: "0.121.0"}

	version, err := Resolve(context.Background(), store, "codex")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got, want := version, "0.121.0"; got != want {
		t.Fatalf("version = %q, want %q", got, want)
	}
}
