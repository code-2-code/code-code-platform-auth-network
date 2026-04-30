package support

import (
	"fmt"
	"strings"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

func ValidateRuntimeCapabilities(pkg *supportv1.CLI) error {
	if pkg == nil {
		return fmt.Errorf("platformk8s/clidefinitions: cli support is nil")
	}
	seen := make(map[supportv1.RuntimeCapabilityKind]struct{}, len(pkg.GetRuntimeCapabilities()))
	for _, capability := range pkg.GetRuntimeCapabilities() {
		if capability == nil {
			return fmt.Errorf("platformk8s/clidefinitions: runtime capability is nil for %q", pkg.GetCliId())
		}
		kind := capability.GetKind()
		if kind == supportv1.RuntimeCapabilityKind_RUNTIME_CAPABILITY_KIND_UNSPECIFIED {
			return fmt.Errorf("platformk8s/clidefinitions: runtime capability kind is unspecified for %q", pkg.GetCliId())
		}
		if _, exists := seen[kind]; exists {
			return fmt.Errorf("platformk8s/clidefinitions: duplicate runtime capability %q for %q", kind.String(), pkg.GetCliId())
		}
		seen[kind] = struct{}{}
		capabilityKey := strings.TrimSpace(capability.GetCapabilityKey())
		if capability.GetSupported() {
			if capabilityKey == "" {
				return fmt.Errorf("platformk8s/clidefinitions: runtime capability %q is missing capability_key for %q", kind.String(), pkg.GetCliId())
			}
			continue
		}
		if capabilityKey != "" {
			return fmt.Errorf("platformk8s/clidefinitions: runtime capability %q must not declare capability_key when unsupported for %q", kind.String(), pkg.GetCliId())
		}
	}
	return nil
}

func ResolveRuntimeCapability(pkg *supportv1.CLI, kind supportv1.RuntimeCapabilityKind) (bool, string, error) {
	if err := ValidateRuntimeCapabilities(pkg); err != nil {
		return false, "", err
	}
	for _, capability := range pkg.GetRuntimeCapabilities() {
		if capability != nil && capability.GetKind() == kind {
			return capability.GetSupported(), capability.GetCapabilityKey(), nil
		}
	}
	return false, "", nil
}
