package authservice

import (
	"strings"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	"code-code.internal/platform-k8s/internal/egressauth"
)

func normalizeHTTPHeaderName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func headerNameSet(names []string) map[string]struct{} {
	if len(names) == 0 {
		return nil
	}
	out := map[string]struct{}{}
	for _, name := range names {
		name = normalizeHTTPHeaderName(name)
		if name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

func normalizedHeaderNames(names []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = normalizeHTTPHeaderName(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func headerNameAllowed(values []string, name string) bool {
	name = normalizeHTTPHeaderName(name)
	for _, value := range values {
		if normalizeHTTPHeaderName(value) == name {
			return true
		}
	}
	return false
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func runtimeMaterialByKey(material map[string]string, key string) (string, bool) {
	key = normalizeRuntimeMaterialKey(key)
	for currentKey, value := range material {
		if normalizeRuntimeMaterialKey(currentKey) == key {
			value = strings.TrimSpace(value)
			if value != "" {
				return value, true
			}
		}
	}
	return "", false
}

func normalizeRuntimeMaterialKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.NewReplacer("-", "_", ".", "_").Replace(value)
}

func skippedEgressRequestAuthResponse() *authv1.ResolveEgressRequestHeadersResponse {
	return &authv1.ResolveEgressRequestHeadersResponse{
		Skipped:       true,
		RemoveHeaders: egressauth.InternalHeaders(),
	}
}

func skippedEgressResponseAuthResponse() *authv1.ResolveEgressResponseHeadersResponse {
	return &authv1.ResolveEgressResponseHeadersResponse{
		Skipped:       true,
		RemoveHeaders: egressauth.InternalHeaders(),
	}
}
