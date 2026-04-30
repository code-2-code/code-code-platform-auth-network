package support

import (
	"testing"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

func TestResolveRuntimeCapabilityReturnsDeclaredSupport(t *testing.T) {
	t.Parallel()

	supported, capabilityKey, err := ResolveRuntimeCapability(&supportv1.CLI{
		CliId: "codex",
		RuntimeCapabilities: []*supportv1.RuntimeCapability{{
			Kind:          supportv1.RuntimeCapabilityKind_RUNTIME_CAPABILITY_KIND_MCP,
			Supported:     true,
			CapabilityKey: "codex.mcp",
		}},
	}, supportv1.RuntimeCapabilityKind_RUNTIME_CAPABILITY_KIND_MCP)
	if err != nil {
		t.Fatalf("ResolveRuntimeCapability() error = %v", err)
	}
	if !supported {
		t.Fatal("supported = false, want true")
	}
	if got, want := capabilityKey, "codex.mcp"; got != want {
		t.Fatalf("capabilityKey = %q, want %q", got, want)
	}
}

func TestValidateRuntimeCapabilitiesRejectsUnsupportedCapabilityKey(t *testing.T) {
	t.Parallel()

	err := ValidateRuntimeCapabilities(&supportv1.CLI{
		CliId: "codex",
		RuntimeCapabilities: []*supportv1.RuntimeCapability{{
			Kind:          supportv1.RuntimeCapabilityKind_RUNTIME_CAPABILITY_KIND_MCP,
			Supported:     false,
			CapabilityKey: "codex.mcp",
		}},
	})
	if err == nil {
		t.Fatal("ValidateRuntimeCapabilities() error = nil, want validation error")
	}
}
