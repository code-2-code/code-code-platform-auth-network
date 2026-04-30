package authservice

import (
	"strings"

	managementv1 "code-code.internal/go-contract/platform/management/v1"
)

func matchesEgressTarget(targetHost string, targetPath string, metadata *managementv1.AgentRunRuntimeMetadata) bool {
	hosts := normalizedHosts(metadata.GetTargetHosts())
	if len(hosts) == 0 {
		return false
	}
	if !matchesEgressTargetHost(targetHost, hosts) {
		return false
	}
	paths := normalizedPathPrefixes(metadata.GetTargetPathPrefixes())
	return len(paths) == 0 || matchesEgressTargetPath(targetPath, paths)
}

func normalizedHosts(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		host := normalizeTargetHost(value)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func matchesEgressTargetHost(value string, allowed []string) bool {
	host := normalizeTargetHost(value)
	if host == "" {
		return false
	}
	for _, candidate := range allowed {
		if host == normalizeTargetHost(candidate) {
			return true
		}
	}
	return false
}

func normalizeTargetHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimSuffix(value, ".")
	if strings.HasPrefix(value, "[") {
		if index := strings.Index(value, "]"); index > 0 {
			return value[1:index]
		}
	}
	if index := strings.LastIndex(value, ":"); index > 0 && !strings.Contains(value[:index], ":") {
		value = value[:index]
	}
	return strings.Trim(value, "[]")
}

func normalizedPathPrefixes(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		prefix := normalizeTargetPath(value)
		if prefix == "" {
			continue
		}
		if prefix != "/" {
			prefix = strings.TrimRight(prefix, "/")
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out
}

func matchesEgressTargetPath(value string, prefixes []string) bool {
	path := normalizeTargetPath(value)
	if path == "" {
		return false
	}
	for _, prefix := range prefixes {
		prefix = normalizeTargetPath(prefix)
		if prefix == "/" || path == prefix || strings.HasPrefix(path, strings.TrimRight(prefix, "/")+"/") || strings.HasPrefix(path, strings.TrimRight(prefix, "/")+":") {
			return true
		}
	}
	return false
}

func normalizeTargetPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if index := strings.IndexAny(value, "?#"); index >= 0 {
		value = value[:index]
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	if value == "" {
		return "/"
	}
	return value
}
