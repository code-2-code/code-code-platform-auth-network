package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
)

func TestAntigravityOAuthAuthorizerRetriesRetryableTokenExchange(t *testing.T) {
	previousDelays := googleOAuthTokenExchangeRetryDelays
	googleOAuthTokenExchangeRetryDelays = []time.Duration{0}
	defer func() { googleOAuthTokenExchangeRetryDelays = previousDelays }()

	client := newOAuthTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	now := time.Date(2026, 4, 17, 8, 0, 0, 0, time.UTC)
	session := &CodeOAuthSession{
		CliID:               string(antigravityCLIID),
		SessionID:           "session-1",
		ProviderRedirectURI: "http://localhost:51121/oauth-callback",
		State:               "state-1",
		CodeVerifier:        "verifier-1",
		ExpiresAt:           now.Add(10 * time.Minute),
	}
	if err := store.PutCodeSession(context.Background(), session); err != nil {
		t.Fatalf("PutCodeSession() error = %v", err)
	}
	tokenAttempts := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenAttempts++
		if tokenAttempts == 1 {
			http.Error(w, "upstream connect error", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token",
			"refresh_token": "refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         strings.Join(defaultAntigravityScopes, " "),
		})
	}))
	defer tokenServer.Close()
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    "google-account-1",
			"email": "user@example.com",
		})
	}))
	defer userInfoServer.Close()
	authorizer, err := NewAntigravityOAuthAuthorizer(AntigravityOAuthAuthorizerConfig{
		SessionStore: store,
		HTTPClientFactory: oauthHTTPClientFactoryStub{
			newClient: func(context.Context) (*http.Client, error) {
				return tokenServer.Client(), nil
			},
		},
		TokenURL:    tokenServer.URL,
		UserInfoURL: userInfoServer.URL,
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAntigravityOAuthAuthorizer() error = %v", err)
	}
	artifact, err := authorizer.CompleteAuthorizationSession(context.Background(), &credentialcontract.OAuthAuthorizationExchange{
		CliID:               antigravityCLIID,
		SessionID:           "session-1",
		Code:                "code-1",
		State:               "state-1",
		ProviderRedirectURI: "http://localhost:51121/oauth-callback",
	})
	if err != nil {
		t.Fatalf("CompleteAuthorizationSession() error = %v", err)
	}
	if got, want := tokenAttempts, 2; got != want {
		t.Fatalf("token attempts = %d, want %d", got, want)
	}
	if got := artifact.AccessToken; got != "access-token" {
		t.Fatalf("AccessToken = %q, want access-token", got)
	}
}
