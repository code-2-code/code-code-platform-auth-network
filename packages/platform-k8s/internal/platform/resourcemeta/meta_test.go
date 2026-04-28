package resourcemeta

import (
	"strings"
	"testing"
)

func TestEnsureResourceID(t *testing.T) {
	t.Parallel()

	got, err := EnsureResourceID("", "Primary Provider", "openai-compatible")
	if err != nil {
		t.Fatalf("EnsureResourceID() error = %v", err)
	}
	if got == "" {
		t.Fatal("EnsureResourceID() returned empty id")
	}
	if got == "primary-provider" {
		t.Fatal("EnsureResourceID() should append a uniqueness suffix")
	}
}

func TestEnsureResourceIDUsesFallback(t *testing.T) {
	t.Parallel()

	got, err := EnsureResourceID("", "中文名称", "openai-compatible")
	if err != nil {
		t.Fatalf("EnsureResourceID() error = %v", err)
	}
	if len(got) == 0 {
		t.Fatal("EnsureResourceID() returned empty id")
	}
	if !strings.HasPrefix(got, "openai-compatible-") {
		t.Fatalf("EnsureResourceID() prefix = %q, want %q prefix", got, "openai-compatible")
	}
}
