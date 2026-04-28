package oauth

import (
	"fmt"
	"net/url"
	"strings"
)

func oauthIssuer(hint string, authorizationURL string) string {
	if value := strings.TrimSpace(hint); value != "" {
		return value
	}
	parsed, err := url.Parse(strings.TrimSpace(authorizationURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func validateIDTokenSessionClaims(provider string, issuer string, nonce string, record *CodeOAuthSession) error {
	if record == nil {
		return fmt.Errorf("platformk8s: %s oauth code session is nil", provider)
	}
	if expected := strings.TrimSpace(record.Issuer); expected != "" {
		if actual := strings.TrimSpace(issuer); actual != "" && actual != expected {
			return fmt.Errorf("platformk8s: %s oauth issuer mismatch", provider)
		}
	}
	if expected := strings.TrimSpace(record.Nonce); expected != "" {
		if actual := strings.TrimSpace(nonce); actual != "" && actual != expected {
			return fmt.Errorf("platformk8s: %s oauth nonce mismatch", provider)
		}
	}
	return nil
}
