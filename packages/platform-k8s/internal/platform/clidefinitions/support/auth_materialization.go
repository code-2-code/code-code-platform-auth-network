package support

import (
	"fmt"
	"net/url"
	"strings"

	apiprotocolv1 "code-code.internal/go-contract/api_protocol/v1"
	credentialv1 "code-code.internal/go-contract/credential/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

func ValidateAuthMaterializations(pkg *supportv1.CLI) error {
	if pkg == nil {
		return fmt.Errorf("platformk8s/clidefinitions: cli support is nil")
	}
	if oauth := pkg.GetOauth(); oauth != nil {
		if err := validateAuthMaterialization(pkg.GetCliId(), "oauth", oauth.GetAuthMaterialization()); err != nil {
			return err
		}
	}
	seen := make(map[apiprotocolv1.Protocol]struct{}, len(pkg.GetApiKeyProtocols()))
	for _, support := range pkg.GetApiKeyProtocols() {
		if support == nil {
			return fmt.Errorf("platformk8s/clidefinitions: api_key_protocol support is nil for %q", pkg.GetCliId())
		}
		protocol := support.GetProtocol()
		if protocol == apiprotocolv1.Protocol_PROTOCOL_UNSPECIFIED {
			return fmt.Errorf("platformk8s/clidefinitions: api_key_protocol is unspecified for %q", pkg.GetCliId())
		}
		if _, ok := seen[protocol]; ok {
			return fmt.Errorf("platformk8s/clidefinitions: duplicate api_key_protocol %q for %q", protocol.String(), pkg.GetCliId())
		}
		seen[protocol] = struct{}{}
		if err := validateAuthMaterialization(pkg.GetCliId(), protocol.String(), support.GetAuthMaterialization()); err != nil {
			return err
		}
	}
	return nil
}

func ResolveAuthMaterialization(pkg *supportv1.CLI, credentialKind credentialv1.CredentialKind, protocol apiprotocolv1.Protocol) (*supportv1.CLIAuthMaterialization, error) {
	if err := ValidateAuthMaterializations(pkg); err != nil {
		return nil, err
	}
	switch credentialKind {
	case credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH:
		if pkg.GetOauth() == nil || pkg.GetOauth().GetAuthMaterialization() == nil {
			return nil, fmt.Errorf("platformk8s/clidefinitions: cli %q does not declare oauth auth materialization", pkg.GetCliId())
		}
		return pkg.GetOauth().GetAuthMaterialization(), nil
	case credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY:
		for _, support := range pkg.GetApiKeyProtocols() {
			if support != nil && support.GetProtocol() == protocol {
				return support.GetAuthMaterialization(), nil
			}
		}
		return nil, fmt.Errorf("platformk8s/clidefinitions: cli %q does not support api key protocol %q", pkg.GetCliId(), protocol.String())
	default:
		return nil, fmt.Errorf("platformk8s/clidefinitions: unsupported credential kind %q for cli %q", credentialKind.String(), pkg.GetCliId())
	}
}

func ResolveTargetHosts(materialization *supportv1.CLIAuthMaterialization, baseURL string) ([]string, error) {
	if materialization == nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: auth materialization is nil")
	}
	hosts := make([]string, 0, len(materialization.GetExtraTargetHosts())+1)
	seen := map[string]struct{}{}
	if materialization.GetIncludeRuntimeUrlHost() {
		host, err := runtimeURLHost(baseURL)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
		seen[host] = struct{}{}
	}
	for _, rawHost := range materialization.GetExtraTargetHosts() {
		host := strings.ToLower(strings.TrimSpace(rawHost))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		hosts = append(hosts, host)
		seen[host] = struct{}{}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("platformk8s/clidefinitions: auth materialization target_hosts are empty")
	}
	return hosts, nil
}

func ResolveTargetPathPrefixes(materialization *supportv1.CLIAuthMaterialization, baseURL string) ([]string, error) {
	if materialization == nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: auth materialization is nil")
	}
	prefixes := normalizedPathPrefixes(materialization.GetTargetPathPrefixes())
	if len(prefixes) > 0 {
		return prefixes, nil
	}
	if !materialization.GetIncludeRuntimeUrlHost() {
		return nil, nil
	}
	normalized, err := normalizeRuntimeURL(baseURL, "runtime_url")
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: parse runtime_url: %w", err)
	}
	path := strings.TrimSpace(parsed.EscapedPath())
	if path == "" || path == "/" {
		return nil, nil
	}
	return []string{normalizePathPrefix(path)}, nil
}

func validateAuthMaterialization(cliID string, scope string, materialization *supportv1.CLIAuthMaterialization) error {
	if materialization == nil {
		return fmt.Errorf("platformk8s/clidefinitions: auth materialization is missing for %q %q", scope, cliID)
	}
	if strings.TrimSpace(materialization.GetMaterializationKey()) == "" {
		return fmt.Errorf("platformk8s/clidefinitions: auth materialization key is empty for %q %q", scope, cliID)
	}
	if materialization.GetRuntimeUrlProjectionKind() == supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_UNSPECIFIED {
		return fmt.Errorf("platformk8s/clidefinitions: runtime_url_projection_kind is unspecified for %q %q", scope, cliID)
	}
	seenProjection := make(map[supportv1.RuntimeProjectionKind]struct{}, len(materialization.GetRequiredRuntimeProjections()))
	for _, kind := range materialization.GetRequiredRuntimeProjections() {
		if kind == supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_UNSPECIFIED {
			return fmt.Errorf("platformk8s/clidefinitions: runtime projection kind is unspecified for %q %q", scope, cliID)
		}
		if _, ok := seenProjection[kind]; ok {
			return fmt.Errorf("platformk8s/clidefinitions: duplicate runtime projection kind %q for %q %q", kind.String(), scope, cliID)
		}
		seenProjection[kind] = struct{}{}
	}
	if materialization.GetRuntimeUrlProjectionKind() == supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_RESOURCE_URL {
		if _, ok := seenProjection[supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_RESOURCE_URL]; !ok {
			return fmt.Errorf("platformk8s/clidefinitions: runtime projection kind %q is required for %q %q", supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_RESOURCE_URL.String(), scope, cliID)
		}
	}
	injection := materialization.GetRequestAuthInjection()
	if injection == nil {
		return fmt.Errorf("platformk8s/clidefinitions: request_auth_injection is missing for %q %q", scope, cliID)
	}
	seenHeader := make(map[string]struct{}, len(injection.GetHeaderNames()))
	for _, rawHeader := range injection.GetHeaderNames() {
		header := strings.ToLower(strings.TrimSpace(rawHeader))
		if header == "" {
			return fmt.Errorf("platformk8s/clidefinitions: request_auth_injection header is empty for %q %q", scope, cliID)
		}
		if _, ok := seenHeader[header]; ok {
			return fmt.Errorf("platformk8s/clidefinitions: duplicate request_auth_injection header %q for %q %q", header, scope, cliID)
		}
		seenHeader[header] = struct{}{}
	}
	if len(seenHeader) == 0 {
		return fmt.Errorf("platformk8s/clidefinitions: request_auth_injection headers are empty for %q %q", scope, cliID)
	}
	if !materialization.GetIncludeRuntimeUrlHost() && len(materialization.GetExtraTargetHosts()) == 0 {
		return fmt.Errorf("platformk8s/clidefinitions: auth materialization must declare at least one target host for %q %q", scope, cliID)
	}
	seenHost := make(map[string]struct{}, len(materialization.GetExtraTargetHosts()))
	for _, rawHost := range materialization.GetExtraTargetHosts() {
		host := strings.ToLower(strings.TrimSpace(rawHost))
		if host == "" {
			return fmt.Errorf("platformk8s/clidefinitions: extra_target_host is empty for %q %q", scope, cliID)
		}
		if strings.Contains(host, "://") {
			return fmt.Errorf("platformk8s/clidefinitions: extra_target_host %q must not include scheme for %q %q", host, scope, cliID)
		}
		if _, ok := seenHost[host]; ok {
			return fmt.Errorf("platformk8s/clidefinitions: duplicate extra_target_host %q for %q %q", host, scope, cliID)
		}
		seenHost[host] = struct{}{}
	}
	seenPath := map[string]struct{}{}
	for _, rawPath := range materialization.GetTargetPathPrefixes() {
		path := normalizePathPrefix(rawPath)
		if path == "" {
			return fmt.Errorf("platformk8s/clidefinitions: target_path_prefix is empty for %q %q", scope, cliID)
		}
		if strings.Contains(path, "://") || strings.Contains(path, "?") || strings.Contains(path, "#") {
			return fmt.Errorf("platformk8s/clidefinitions: target_path_prefix %q must be a path only for %q %q", path, scope, cliID)
		}
		if _, ok := seenPath[path]; ok {
			return fmt.Errorf("platformk8s/clidefinitions: duplicate target_path_prefix %q for %q %q", path, scope, cliID)
		}
		seenPath[path] = struct{}{}
	}
	return nil
}

func normalizedPathPrefixes(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		prefix := normalizePathPrefix(value)
		if prefix == "" {
			continue
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out
}

func normalizePathPrefix(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		return value
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	if value != "/" {
		value = strings.TrimRight(value, "/")
	}
	return value
}
