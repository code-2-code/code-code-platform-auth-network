package support

import (
	"context"
	"testing"
)

func TestSupportListReturnsRegisteredVendors(t *testing.T) {
	svc, err := NewManagementService()
	if err != nil {
		t.Fatalf("NewManagementService() error = %v", err)
	}

	items, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := len(items), len(staticVendorYAMLIDs()); got != want {
		t.Fatalf("items = %d, want %d", got, want)
	}
	item, err := svc.Get(context.Background(), "openai")
	if err != nil {
		t.Fatalf("Get(openai) error = %v", err)
	}
	if item.GetVendor().GetDisplayName() != "OpenAI" {
		t.Fatalf("display_name = %q, want OpenAI", item.GetVendor().GetDisplayName())
	}
	if len(item.GetProviderBindings()) == 0 {
		t.Fatal("openai provider_bindings = 0, want registered bindings")
	}
}
