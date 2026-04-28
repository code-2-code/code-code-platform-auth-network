package googleaistudio

import (
	"strings"
	"testing"
	"time"

	"code-code.internal/platform-k8s/internal/egressauth"
)

func TestReplaceHeaderAuthorization(t *testing.T) {
	got, ok := ReplaceHeader(egressauth.ReplacementInput{
		HeaderName:   "authorization",
		CurrentValue: egressauth.Placeholder,
		Origin:       "https://aistudio.google.com",
		Now:          time.Unix(1700000000, 0),
		Material: map[string]string{
			"cookie": "SAPISID=sapisid; __Secure-1PAPISID=one; __Secure-3PAPISID=three",
		},
	})
	if !ok {
		t.Fatal("ReplaceHeader() ok = false")
	}
	for _, prefix := range []string{"SAPISIDHASH 1700000000_", "SAPISID1PHASH 1700000000_", "SAPISID3PHASH 1700000000_"} {
		if !strings.Contains(got, prefix) {
			t.Fatalf("ReplaceHeader() = %q, missing %q", got, prefix)
		}
	}
}

func TestReplaceHeaderPageAPIKey(t *testing.T) {
	got, ok := ReplaceHeader(egressauth.ReplacementInput{
		HeaderName:   "x-goog-api-key",
		CurrentValue: egressauth.Placeholder,
		Material: map[string]string{
			"page_api_key": "page-key",
			"api_key":      "fallback-key",
		},
	})
	if !ok {
		t.Fatal("ReplaceHeader() ok = false")
	}
	if got != "page-key" {
		t.Fatalf("ReplaceHeader() = %q, want %q", got, "page-key")
	}
}

func TestReplaceHeaderFallsBackToSessionCookie(t *testing.T) {
	got, ok := ReplaceHeader(egressauth.ReplacementInput{
		HeaderName:   "cookie",
		CurrentValue: "authjs.session-token=" + egressauth.Placeholder,
		Material: map[string]string{
			"authjs_session_token": "session-token",
		},
	})
	if !ok {
		t.Fatal("ReplaceHeader() ok = false")
	}
	if got != "authjs.session-token=session-token" {
		t.Fatalf("ReplaceHeader() = %q", got)
	}
}
