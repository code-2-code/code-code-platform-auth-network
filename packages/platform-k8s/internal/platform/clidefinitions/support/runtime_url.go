package support

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
)

func ResolveRuntimeURL(
	materialization *supportv1.CLIAuthMaterialization,
	providerBaseURL string,
	artifact *credentialcontract.OAuthArtifact,
) (string, error) {
	if materialization == nil {
		return "", fmt.Errorf("platformk8s/clidefinitions: auth materialization is nil")
	}
	switch materialization.GetRuntimeUrlProjectionKind() {
	case supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_BASE_URL:
		return normalizeRuntimeURL(providerBaseURL, "provider surface base_url")
	case supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_RESOURCE_URL:
		return normalizeRuntimeURL(resourceURLFromArtifact(artifact), "oauth artifact resource_url")
	default:
		return "", fmt.Errorf("platformk8s/clidefinitions: runtime_url_projection_kind is unspecified")
	}
}

func runtimeURLHost(rawURL string) (string, error) {
	normalized, err := normalizeRuntimeURL(rawURL, "runtime_url")
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", fmt.Errorf("platformk8s/clidefinitions: parse runtime_url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return "", fmt.Errorf("platformk8s/clidefinitions: runtime_url host is empty")
	}
	return host, nil
}

func resourceURLFromArtifact(artifact *credentialcontract.OAuthArtifact) string {
	if artifact == nil {
		return ""
	}
	response := struct {
		ResourceURL string `json:"resource_url"`
	}{}
	if json.Unmarshal([]byte(strings.TrimSpace(artifact.TokenResponseJSON)), &response) != nil {
		return ""
	}
	return strings.TrimSpace(response.ResourceURL)
}

func normalizeRuntimeURL(rawURL string, source string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", fmt.Errorf("platformk8s/clidefinitions: %s is empty", source)
	}
	parseValue := trimmed
	if !strings.Contains(parseValue, "://") {
		parseValue = "https://" + parseValue
	}
	parsed, err := url.Parse(parseValue)
	if err != nil {
		return "", fmt.Errorf("platformk8s/clidefinitions: parse %s: %w", source, err)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("platformk8s/clidefinitions: %s must not include credentials", source)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("platformk8s/clidefinitions: %s must not include query or fragment", source)
	}
	if strings.TrimSpace(parsed.Hostname()) == "" {
		return "", fmt.Errorf("platformk8s/clidefinitions: %s host is empty", source)
	}
	normalized := parsed.Scheme + "://" + parsed.Host
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	if path != "" {
		normalized += path
	}
	return normalized, nil
}
