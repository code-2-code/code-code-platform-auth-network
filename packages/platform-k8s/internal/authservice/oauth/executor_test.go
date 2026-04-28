package oauth

import (
	"context"
	"testing"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
)

type countingCodeAuthorizer struct {
	calls int
}

func (a *countingCodeAuthorizer) StartAuthorizationSession(context.Context, *credentialcontract.OAuthAuthorizationRequest) (*credentialcontract.OAuthAuthorizationSession, error) {
	return nil, nil
}

func (a *countingCodeAuthorizer) CompleteAuthorizationSession(context.Context, *credentialcontract.OAuthAuthorizationExchange) (*credentialcontract.OAuthArtifact, error) {
	a.calls += 1
	return &credentialcontract.OAuthArtifact{
		AccessToken: "unexpected-access-token",
	}, nil
}

type noopOAuthImporter struct{}

func (noopOAuthImporter) ImportOAuthCredential(context.Context, *credentialcontract.OAuthImportRequest) (*credentialcontract.CredentialDefinition, error) {
	return &credentialcontract.CredentialDefinition{}, nil
}

func TestSessionExecutorExchangeCodeReusesStoredArtifact(t *testing.T) {
	client := newOAuthTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	if err := store.PutCodeSession(context.Background(), &CodeOAuthSession{
		CliID:               "antigravity",
		SessionID:           "session-artifact-1",
		ProviderRedirectURI: "http://localhost:51121/oauth-callback",
		State:               "state-1",
		CodeVerifier:        "verifier-1",
		ExpiresAt:           time.Date(2026, 4, 18, 18, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("PutCodeSession() error = %v", err)
	}
	if err := store.PutCodeCallback(context.Background(), "antigravity", "session-artifact-1", &OAuthCodeCallbackPayload{
		Code:                "auth-code-1",
		State:               "state-1",
		ProviderRedirectURI: "http://localhost:51121/oauth-callback",
		ReceivedAt:          time.Date(2026, 4, 18, 17, 55, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("PutCodeCallback() error = %v", err)
	}
	if err := store.PutArtifact(context.Background(), "antigravity", "session-artifact-1", &credentialcontract.OAuthArtifact{
		AccessToken:  "stored-access-token",
		RefreshToken: "stored-refresh-token",
		TokenType:    "Bearer",
	}); err != nil {
		t.Fatalf("PutArtifact() error = %v", err)
	}
	authorizer := &countingCodeAuthorizer{}
	executor, err := NewSessionExecutor(SessionExecutorConfig{
		Registry: sessionAuthorizerRegistryStub{
			code: authorizer,
		},
		Importer:     noopOAuthImporter{},
		SessionStore: store,
	})
	if err != nil {
		t.Fatalf("NewSessionExecutor() error = %v", err)
	}

	artifact, err := executor.ExchangeCode(context.Background(), &platformv1alpha1.OAuthAuthorizationSessionResource{
		Spec: platformv1alpha1.OAuthAuthorizationSessionSpec{
			CliID:     "antigravity",
			SessionID: "session-artifact-1",
		},
	})
	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}
	if got, want := artifact.AccessToken, "stored-access-token"; got != want {
		t.Fatalf("access_token = %q, want %q", got, want)
	}
	if got := authorizer.calls; got != 0 {
		t.Fatalf("CompleteAuthorizationSession calls = %d, want 0", got)
	}
}
