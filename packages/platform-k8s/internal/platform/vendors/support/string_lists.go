package support

import (
	"slices"
	"strings"
)

func sourceServiceAccounts(defaults []string, overrides []string) []string {
	if len(overrides) > 0 {
		return append([]string{}, overrides...)
	}
	return append([]string{}, defaults...)
}

func normalizeStringList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}
