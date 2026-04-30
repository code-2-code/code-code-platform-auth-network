package identity

import (
	"context"
	"testing"

	managementv1 "code-code.internal/go-contract/platform/management/v1"
)

func TestListReturnsRegisteredVendors(t *testing.T) {
	svc, err := NewVendorManagementService()
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	items, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got, want := len(items), len(staticVendorYAMLIDs()); got != want {
		t.Fatalf("items = %d, want %d", got, want)
	}
	if vendor := findVendor(items, "openai"); vendor == nil {
		t.Fatal("openai vendor not found")
	} else if vendor.GetDisplayName() != "OpenAI" {
		t.Fatalf("openai display_name = %q, want OpenAI", vendor.GetDisplayName())
	}
	if vendor := findVendor(items, "google"); vendor == nil {
		t.Fatal("google vendor not found")
	}
}

func TestLoadIndexReturnsRegisteredVendor(t *testing.T) {
	index, err := LoadIndex(context.Background())
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	vendor := index.Get("openai")
	if vendor == nil {
		t.Fatal("openai vendor not found")
	}
	if vendor.GetWebsiteUrl() != "https://openai.com" {
		t.Fatalf("openai website_url = %q, want https://openai.com", vendor.GetWebsiteUrl())
	}
}

func findVendor(items []*managementv1.VendorView, vendorID string) *managementv1.VendorView {
	for _, item := range items {
		if item.GetVendorId() == vendorID {
			return item
		}
	}
	return nil
}
