package credentials

import (
	"net/url"
	"strings"
)

func baseURLHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil {
		return ""
	}
	return parsed.Host
}
