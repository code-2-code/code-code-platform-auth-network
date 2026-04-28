package credentials

import (
	"strings"

	modelcatalogdiscoveryv1 "code-code.internal/go-contract/model_catalog_discovery/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

const antigravityProbeCLIID = "antigravity"

var antigravityOAuthProbeBaseURLs = []string{
	"https://daily-cloudcode-pa.sandbox.googleapis.com",
	"https://daily-cloudcode-pa.googleapis.com",
	"https://cloudcode-pa.googleapis.com",
}

func init() {
	registerCLIOAuthProbeBaseURLResolver(antigravityProbeCLIID, resolveAntigravityOAuthProbeBaseURLs)
}

func resolveAntigravityOAuthProbeBaseURLs(
	_ *supportv1.CLI,
	operation *modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation,
	effectiveBaseURL string,
) []string {
	if !isAntigravityOAuthProbeFallbackEnabled(operation, effectiveBaseURL) {
		return []string{effectiveBaseURL}
	}
	return append([]string(nil), antigravityOAuthProbeBaseURLs...)
}

func isAntigravityOAuthProbeFallbackEnabled(
	operation *modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation,
	baseURL string,
) bool {
	if operation == nil {
		return false
	}
	if operation.GetResponseKind() != modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_ANTIGRAVITY_MODELS_MAP {
		return false
	}
	path := strings.TrimPrefix(strings.TrimSpace(operation.GetPath()), "/")
	if path != "v1internal:fetchAvailableModels" {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(baseURLHost(baseURL)))
	switch host {
	case "daily-cloudcode-pa.sandbox.googleapis.com", "daily-cloudcode-pa.googleapis.com", "cloudcode-pa.googleapis.com":
		return true
	default:
		return false
	}
}
