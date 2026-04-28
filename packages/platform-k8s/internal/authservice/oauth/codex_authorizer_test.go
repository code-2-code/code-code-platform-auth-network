package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
)

type oauthHTTPClientFactoryStub struct {
	newClient func(context.Context) (*http.Client, error)
}

func (s oauthHTTPClientFactoryStub) NewClient(ctx context.Context) (*http.Client, error) {
	return s.newClient(ctx)
}

func TestCodexOAuthAuthorizerStartAuthorizationSession(t *testing.T) {
	client := newOAuthTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	now := time.Date(2026, 4, 13, 10, 0, 0, 0, time.UTC)
	authorizer, err := NewCodexOAuthAuthorizer(CodexOAuthAuthorizerConfig{
		SessionStore: store,
		HTTPClientFactory: oauthHTTPClientFactoryStub{
			newClient: func(context.Context) (*http.Client, error) {
				return http.DefaultClient, nil
			},
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewCodexOAuthAuthorizer() error = %v", err)
	}

	session, err := authorizer.StartAuthorizationSession(context.Background(), &credentialcontract.OAuthAuthorizationRequest{
		CliID:               "codex",
		ProviderRedirectURI: "http://localhost:1455/auth/callback",
	})
	if err != nil {
		t.Fatalf("StartAuthorizationSession() error = %v", err)
	}
	if session.CliID != "codex" {
		t.Fatalf("CliID = %q, want codex", session.CliID)
	}
	record, err := store.GetCodeSession(context.Background(), "codex", session.SessionID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if record.ProviderRedirectURI != "http://localhost:1455/auth/callback" {
		t.Fatalf("ProviderRedirectURI = %q, want callback uri", record.ProviderRedirectURI)
	}

	parsed, err := url.Parse(session.AuthorizationURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	query := parsed.Query()
	if query.Get("client_id") != defaultCodexClientID {
		t.Fatalf("client_id = %q, want %q", query.Get("client_id"), defaultCodexClientID)
	}
	if query.Get("state") != record.State {
		t.Fatalf("state = %q, want %q", query.Get("state"), record.State)
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", query.Get("code_challenge_method"))
	}
}

func TestCodexOAuthAuthorizerCompleteAuthorizationSession(t *testing.T) {
	client := newOAuthTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	now := time.Date(2026, 4, 13, 10, 0, 0, 0, time.UTC)
	session := &CodeOAuthSession{
		CliID:               "codex",
		SessionID:           "session-1",
		ProviderRedirectURI: "http://localhost:1455/auth/callback",
		State:               "state-1",
		CodeVerifier:        "verifier-1",
		ExpiresAt:           now.Add(10 * time.Minute),
	}
	if err := store.PutCodeSession(context.Background(), session); err != nil {
		t.Fatalf("PutCodeSession() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("code_verifier"); got != "verifier-1" {
			t.Fatalf("code_verifier = %q, want verifier-1", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token",
			"refresh_token": "refresh-token",
			"id_token":      newTestCodexIDToken("user@example.com", "acct-1"),
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "openid email profile offline_access",
		})
	}))
	defer server.Close()

	authorizer, err := NewCodexOAuthAuthorizer(CodexOAuthAuthorizerConfig{
		SessionStore: store,
		HTTPClientFactory: oauthHTTPClientFactoryStub{
			newClient: func(context.Context) (*http.Client, error) {
				return server.Client(), nil
			},
		},
		TokenURL: server.URL,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewCodexOAuthAuthorizer() error = %v", err)
	}

	artifact, err := authorizer.CompleteAuthorizationSession(context.Background(), &credentialcontract.OAuthAuthorizationExchange{
		CliID:               "codex",
		SessionID:           "session-1",
		Code:                "code-1",
		State:               "state-1",
		ProviderRedirectURI: "http://localhost:1455/auth/callback",
	})
	if err != nil {
		t.Fatalf("CompleteAuthorizationSession() error = %v", err)
	}
	if artifact.AccessToken != "access-token" {
		t.Fatalf("AccessToken = %q, want access-token", artifact.AccessToken)
	}
	if artifact.AccountEmail != "user@example.com" {
		t.Fatalf("AccountEmail = %q, want user@example.com", artifact.AccountEmail)
	}
	if artifact.AccountID != "acct-1" {
		t.Fatalf("AccountID = %q, want acct-1", artifact.AccountID)
	}
	if len(artifact.Scopes) != 4 {
		t.Fatalf("Scopes = %#v, want 4 entries", artifact.Scopes)
	}
	if _, err := store.GetCodeSession(context.Background(), "codex", "session-1"); err != nil {
		t.Fatalf("GetCodeSession() after complete error = %v, want nil", err)
	}
}

func newTestCodexIDToken(email, accountID string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"` + email + `","https://api.openai.com/auth":{"chatgpt_account_id":"` + accountID + `"}}`))
	return strings.Join([]string{header, payload, "signature"}, ".")
}
