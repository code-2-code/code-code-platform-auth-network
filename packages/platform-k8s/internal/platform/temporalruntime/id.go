package temporalruntime

import (
	"strings"
)

func IDPart(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_' || r == '.' || r == ':':
			builder.WriteByte('-')
		}
	}
	out := strings.Trim(builder.String(), "-")
	if out == "" {
		out = strings.TrimSpace(fallback)
	}
	if out == "" {
		return "unknown"
	}
	if len(out) > 80 {
		out = strings.TrimRight(out[:80], "-")
	}
	return out
}
