package support

import (
	"context"
	"testing"
)

func TestSupportListReturnsRegisteredCLIs(t *testing.T) {
	t.Parallel()

	svc, err := NewManagementService()
	if err != nil {
		t.Fatalf("NewManagementService() error = %v", err)
	}

	items, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != len(staticCLIYAMLIDs()) {
		t.Fatalf("items = %d, want %d", len(items), len(staticCLIYAMLIDs()))
	}
	codex, err := svc.Get(context.Background(), "codex")
	if err != nil {
		t.Fatalf("Get(codex) error = %v", err)
	}
	if codex.GetDisplayName() != "Codex CLI" {
		t.Fatalf("codex display_name = %q", codex.GetDisplayName())
	}
}
