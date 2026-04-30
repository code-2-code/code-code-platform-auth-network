package oauth

import (
	"net/http"
	"strings"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

const clientVersionTemplateVariable = "${client_version}"

type ResolvedOAuthClientIdentity struct {
	ClientVersion          string
	ModelCatalogUserAgent  string
	ObservabilityUserAgent string
}

func ResolveOAuthClientIdentity(
	pkg *supportv1.CLI,
	clientVersion string,
) ResolvedOAuthClientIdentity {
	identity := ResolvedOAuthClientIdentity{
		ClientVersion: strings.TrimSpace(clientVersion),
	}
	if pkg == nil || pkg.GetOauth() == nil || pkg.GetOauth().GetClientIdentity() == nil {
		return identity
	}
	config := pkg.GetOauth().GetClientIdentity()
	identity.ModelCatalogUserAgent = renderClientIdentityTemplate(config.GetModelCatalogUserAgentTemplate(), identity.ClientVersion)
	identity.ObservabilityUserAgent = renderClientIdentityTemplate(config.GetObservabilityUserAgentTemplate(), identity.ClientVersion)
	return identity
}

func ApplyOAuthProbeClientIdentityHeaders(
	headers http.Header,
	pkg *supportv1.CLI,
	clientVersion string,
) http.Header {
	if headers == nil {
		headers = make(http.Header)
	} else {
		headers = headers.Clone()
	}
	identity := ResolveOAuthClientIdentity(pkg, clientVersion)
	if headers.Get("User-Agent") == "" && identity.ModelCatalogUserAgent != "" {
		headers.Set("User-Agent", identity.ModelCatalogUserAgent)
	}
	return headers
}

func renderClientIdentityTemplate(template string, clientVersion string) string {
	trimmed := strings.TrimSpace(template)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, clientVersionTemplateVariable) {
		clientVersion = strings.TrimSpace(clientVersion)
		if clientVersion == "" {
			return ""
		}
		trimmed = strings.ReplaceAll(trimmed, clientVersionTemplateVariable, clientVersion)
	}
	return strings.TrimSpace(trimmed)
}
