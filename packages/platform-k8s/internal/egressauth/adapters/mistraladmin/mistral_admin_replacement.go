package mistraladmin

import (
	"strings"

	"code-code.internal/platform-k8s/internal/egressauth"
	"code-code.internal/platform-k8s/internal/sessioncookie"
)

const (
	AdapterID            = "mistral-admin-session"
	csrfCookieName       = "csrftoken"
	httpHeaderXCSRFToken = "x-csrftoken"
)

func ReplaceHeader(input egressauth.ReplacementInput) (string, bool) {
	headerName := strings.ToLower(strings.TrimSpace(input.HeaderName))
	current := strings.TrimSpace(input.CurrentValue)
	if headerName == "" || !strings.Contains(current, egressauth.Placeholder) {
		return "", false
	}
	switch headerName {
	case egressauth.HTTPHeaderCookie:
		return replacementValue(current, cookieHeaderMaterial(input.Material))
	case httpHeaderXCSRFToken:
		token := csrfTokenFromCookieHeader(cookieHeaderMaterial(input.Material))
		if token == "" {
			return "", true
		}
		return replacementValue(current, token)
	default:
		return "", false
	}
}

func replacementValue(current string, token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	current = strings.TrimSpace(current)
	if current == egressauth.Placeholder {
		return token, true
	}
	if strings.Contains(current, egressauth.Placeholder) {
		return strings.ReplaceAll(current, egressauth.Placeholder, token), true
	}
	return "", false
}

func cookieHeaderMaterial(material map[string]string) string {
	return materialByKey(material, egressauth.MaterialKeyCookie)
}

func materialByKey(material map[string]string, key string) string {
	key = normalizeMaterialKey(key)
	for currentKey, value := range material {
		if normalizeMaterialKey(currentKey) == key {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func normalizeMaterialKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("-", "_", ".", "_")
	return replacer.Replace(value)
}

func csrfTokenFromCookieHeader(cookieHeader string) string {
	return sessioncookie.Value(cookieHeader, csrfCookieName)
}
