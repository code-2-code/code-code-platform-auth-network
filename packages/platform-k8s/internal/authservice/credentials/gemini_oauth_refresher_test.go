package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGeminiOAuthRefresherRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("client_id"); got != geminiClientID {
			t.Fatalf("client_id = %q, want %q", got, geminiClientID)
		}
		if got := r.Form.Get("client_secret"); got != geminiClientSecret {
			t.Fatalf("client_secret = %q, want %q", got, geminiClientSecret)
		}
		if got := r.Form.Get("refresh_token"); got != "refresh-token" {
			t.Fatalf("refresh_token = %q, want refresh-token", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token",
			"refresh_token": "next-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "scope-a scope-b",
		})
	}))
	defer server.Close()

	refresher := NewGeminiOAuthRefresher(GeminiOAuthRefresherConfig{
		TokenURL: server.URL,
	})

	result, err := refresher.Refresh(context.Background(), server.Client(), "refresh-token")
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := result.AccessToken; got != "access-token" {
		t.Fatalf("AccessToken = %q, want access-token", got)
	}
	if got := result.RefreshToken; got != "next-refresh-token" {
		t.Fatalf("RefreshToken = %q, want next-refresh-token", got)
	}
	if got := len(result.Scopes); got != 2 {
		t.Fatalf("Scopes len = %d, want 2", got)
	}
}

func TestGeminiOAuthRefresherIsNonRetryable(t *testing.T) {
	refresher := NewGeminiOAuthRefresher(GeminiOAuthRefresherConfig{})
	if !refresher.IsNonRetryable(errors.New("credentials: gemini refresh failed: invalid_grant - Token has been expired or revoked")) {
		t.Fatal("IsNonRetryable() = false, want true")
	}
	if refresher.IsNonRetryable(errors.New("credentials: gemini refresh request: timeout")) {
		t.Fatal("IsNonRetryable() = true, want false")
	}
}
