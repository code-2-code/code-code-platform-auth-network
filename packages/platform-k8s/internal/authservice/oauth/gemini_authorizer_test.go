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

func TestGeminiOAuthAuthorizerStartAuthorizationSession(t *testing.T) {
	client := newOAuthTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	now := time.Date(2026, 4, 15, 10, 0, 0, 0, time.UTC)
	authorizer, err := NewGeminiOAuthAuthorizer(GeminiOAuthAuthorizerConfig{
		SessionStore: store,
		HTTPClientFactory: oauthHTTPClientFactoryStub{
			newClient: func(context.Context) (*http.Client, error) {
				return http.DefaultClient, nil
			},
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewGeminiOAuthAuthorizer() error = %v", err)
	}

	session, err := authorizer.StartAuthorizationSession(context.Background(), &credentialcontract.OAuthAuthorizationRequest{
		CliID:               geminiCLIID,
		ProviderRedirectURI: "http://localhost:1455/auth/callback",
	})
	if err != nil {
		t.Fatalf("StartAuthorizationSession() error = %v", err)
	}
	if session.CliID != geminiCLIID {
		t.Fatalf("CliID = %q, want %q", session.CliID, geminiCLIID)
	}
	record, err := store.GetCodeSession(context.Background(), geminiCLIID, session.SessionID)
	if err != nil {
		t.Fatalf("GetCodeSession() error = %v", err)
	}
	parsed, err := url.Parse(session.AuthorizationURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	query := parsed.Query()
	if got := query.Get("client_id"); got != defaultGeminiClientID {
		t.Fatalf("client_id = %q, want %q", got, defaultGeminiClientID)
	}
	if got := query.Get("state"); got != record.State {
		t.Fatalf("state = %q, want %q", got, record.State)
	}
	if got := query.Get("access_type"); got != "offline" {
		t.Fatalf("access_type = %q, want offline", got)
	}
	if got := query.Get("prompt"); got != "consent" {
		t.Fatalf("prompt = %q, want consent", got)
	}
	if got := query.Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", got)
	}
	if !strings.Contains(query.Get("scope"), "cloud-platform") {
		t.Fatalf("scope = %q, want cloud-platform", query.Get("scope"))
	}
}

func TestGeminiOAuthAuthorizerCompleteAuthorizationSession(t *testing.T) {
	client := newOAuthTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	now := time.Date(2026, 4, 15, 10, 0, 0, 0, time.UTC)
	session := &CodeOAuthSession{
		CliID:               geminiCLIID,
		SessionID:           "session-1",
		ProviderRedirectURI: "http://localhost:1455/auth/callback",
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
		if got := r.Form.Get("client_secret"); got != defaultGeminiClientSecret {
			t.Fatalf("client_secret = %q, want %q", got, defaultGeminiClientSecret)
		}
		if got := r.Form.Get("code_verifier"); got != "verifier-1" {
			t.Fatalf("code_verifier = %q, want verifier-1", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token",
			"refresh_token": "refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         strings.Join(defaultGeminiScopes, " "),
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

	authorizer, err := NewGeminiOAuthAuthorizer(GeminiOAuthAuthorizerConfig{
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
		t.Fatalf("NewGeminiOAuthAuthorizer() error = %v", err)
	}

	artifact, err := authorizer.CompleteAuthorizationSession(context.Background(), &credentialcontract.OAuthAuthorizationExchange{
		CliID:               geminiCLIID,
		SessionID:           "session-1",
		Code:                "code-1",
		State:               "state-1",
		ProviderRedirectURI: "http://localhost:1455/auth/callback",
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
	if got := artifact.AccountID; got != "google-account-1" {
		t.Fatalf("AccountID = %q, want google-account-1", got)
	}
	if len(artifact.Scopes) != len(defaultGeminiScopes) {
		t.Fatalf("Scopes = %#v, want %d entries", artifact.Scopes, len(defaultGeminiScopes))
	}
}
