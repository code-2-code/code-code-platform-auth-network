package credentials

import (
	"strings"

	modelcatalogdiscoveryv1 "code-code.internal/go-contract/model_catalog_discovery/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

type cliOAuthProbeBaseURLResolver func(
	pkg *supportv1.CLI,
	operation *modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation,
	effectiveBaseURL string,
) []string

var cliOAuthProbeBaseURLResolvers = map[string]cliOAuthProbeBaseURLResolver{}

func registerCLIOAuthProbeBaseURLResolver(cliID string, resolver cliOAuthProbeBaseURLResolver) {
	trimmedCLIID := strings.TrimSpace(cliID)
	if trimmedCLIID == "" || resolver == nil {
		return
	}
	cliOAuthProbeBaseURLResolvers[trimmedCLIID] = resolver
}

func resolveCLIOAuthProbeBaseURLs(
	pkg *supportv1.CLI,
	operation *modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation,
	baseURL string,
) []string {
	effectiveBaseURL := strings.TrimSpace(baseURL)
	if operation != nil {
		if override := strings.TrimSpace(operation.GetBaseUrl()); override != "" {
			effectiveBaseURL = override
		}
	}
	if effectiveBaseURL == "" {
		return nil
	}
	cliID := ""
	if pkg != nil {
		cliID = strings.TrimSpace(pkg.GetCliId())
	}
	if resolver, ok := cliOAuthProbeBaseURLResolvers[cliID]; ok {
		return resolver(pkg, operation, effectiveBaseURL)
	}
	return []string{effectiveBaseURL}
}
