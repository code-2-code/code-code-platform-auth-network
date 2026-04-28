package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAntigravityOAuthRefresherRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("client_id"); got != antigravityClientID {
			t.Fatalf("client_id = %q, want %q", got, antigravityClientID)
		}
		if got := r.Form.Get("client_secret"); got != antigravityClientSecret {
			t.Fatalf("client_secret = %q, want %q", got, antigravityClientSecret)
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

	refresher := NewAntigravityOAuthRefresher(AntigravityOAuthRefresherConfig{
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
}

func TestAntigravityOAuthRefresherIsNonRetryable(t *testing.T) {
	refresher := NewAntigravityOAuthRefresher(AntigravityOAuthRefresherConfig{})
	if !refresher.IsNonRetryable(errors.New("credentials: antigravity refresh failed: invalid_grant - expired")) {
		t.Fatal("IsNonRetryable() = false, want true")
	}
	if refresher.IsNonRetryable(errors.New("credentials: antigravity refresh request: timeout")) {
		t.Fatal("IsNonRetryable() = true, want false")
	}
}
