package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
)

func TestAntigravityOAuthAuthorizerStartAuthorizationSession(t *testing.T) {
	client := newOAuthTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	now := time.Date(2026, 4, 17, 8, 0, 0, 0, time.UTC)
	authorizer, err := NewAntigravityOAuthAuthorizer(AntigravityOAuthAuthorizerConfig{
		SessionStore: store,
		HTTPClientFactory: oauthHTTPClientFactoryStub{
			newClient: func(context.Context) (*http.Client, error) {
				return http.DefaultClient, nil
			},
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAntigravityOAuthAuthorizer() error = %v", err)
	}
	session, err := authorizer.StartAuthorizationSession(context.Background(), &credentialcontract.OAuthAuthorizationRequest{
		CliID:               antigravityCLIID,
		ProviderRedirectURI: "http://localhost:51121/oauth-callback",
	})
	if err != nil {
		t.Fatalf("StartAuthorizationSession() error = %v", err)
	}
	record, err := store.GetCodeSession(context.Background(), string(antigravityCLIID), session.SessionID)
	if err != nil {
		t.Fatalf("GetCodeSession() error = %v", err)
	}
	parsed, err := url.Parse(session.AuthorizationURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	query := parsed.Query()
	if got := query.Get("client_id"); got != defaultAntigravityClientID {
		t.Fatalf("client_id = %q, want %q", got, defaultAntigravityClientID)
	}
	if got := query.Get("state"); got != record.State {
		t.Fatalf("state = %q, want %q", got, record.State)
	}
	if got := query.Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", got)
	}
	if !strings.Contains(query.Get("scope"), "experimentsandconfigs") {
		t.Fatalf("scope = %q, want experimentsandconfigs", query.Get("scope"))
	}
}

func TestAntigravityOAuthAuthorizerCompleteAuthorizationSession(t *testing.T) {
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
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("client_secret"); got != defaultAntigravityClientSecret {
			t.Fatalf("client_secret = %q, want %q", got, defaultAntigravityClientSecret)
		}
		if got := r.Form.Get("code_verifier"); got != "verifier-1" {
			t.Fatalf("code_verifier = %q, want verifier-1", got)
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
		if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
			t.Fatalf("Authorization = %q, want Bearer access-token", got)
		}
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
	if got := artifact.AccessToken; got != "access-token" {
		t.Fatalf("AccessToken = %q, want access-token", got)
	}
	if got := artifact.AccountEmail; got != "user@example.com" {
		t.Fatalf("AccountEmail = %q, want user@example.com", got)
	}
}
