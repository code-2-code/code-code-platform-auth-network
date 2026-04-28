package cliversions

import (
	"testing"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

func TestResolveSourceReturnsOfficialVersionSource(t *testing.T) {
	source, ok, err := ResolveSource(&supportv1.CLI{
		CliId: "codex",
		OfficialVersionSource: &supportv1.OfficialVersionSource{
			Source: &supportv1.OfficialVersionSource_NpmDistTag{
				NpmDistTag: &supportv1.NPMRegistryVersionSource{
					PackageName: "@openai/codex",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("ResolveSource() error = %v", err)
	}
	if !ok {
		t.Fatal("ResolveSource() ok = false, want true")
	}
	if got, want := source.PackageName, "@openai/codex"; got != want {
		t.Fatalf("package name = %q, want %q", got, want)
	}
}
