package oauth

import (
	"strings"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

func filterOAuthProbeModelIDs(
	pkg *supportv1.CLI,
	modelIDs []string,
) []string {
	if strings.TrimSpace(pkg.GetCliId()) != "antigravity" {
		return modelIDs
	}
	return filterAntigravityProbeModelIDs(modelIDs)
}

func filterAntigravityProbeModelIDs(modelIDs []string) []string {
	filtered := make([]string, 0, len(modelIDs))
	for _, rawModelID := range modelIDs {
		modelID := strings.TrimSpace(rawModelID)
		if !antigravityProbeModelSupported(modelID) {
			continue
		}
		filtered = append(filtered, modelID)
	}
	return filtered
}

func antigravityProbeModelSupported(modelID string) bool {
	normalized := strings.ToLower(strings.TrimSpace(modelID))
	return strings.HasPrefix(normalized, "gemini") ||
		strings.HasPrefix(normalized, "claude") ||
		strings.HasPrefix(normalized, "gpt") ||
		strings.HasPrefix(normalized, "image") ||
		strings.HasPrefix(normalized, "imagen")
}
