package oauth

import (
	"context"
	"testing"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSessionManagerRecordCodeCallbackReturnsRecordedEvent(t *testing.T) {
	client := newOAuthSessionManagerTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	if err := store.PutCodeSession(context.Background(), &CodeOAuthSession{
		CliID:               "codex",
		SessionID:           "session-1",
		ProviderRedirectURI: "http://localhost:1455/auth/callback",
		State:               "state-1",
		CodeVerifier:        "verifier-1",
		ExpiresAt:           time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("PutCodeSession() error = %v", err)
	}
	resource := &platformv1alpha1.OAuthAuthorizationSessionResource{
		ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "code-code"},
		Spec: platformv1alpha1.OAuthAuthorizationSessionSpec{
			SessionID: "session-1",
			CliID:     "codex",
			Flow:      platformv1alpha1.OAuthAuthorizationSessionFlowCode,
		},
		Status: platformv1alpha1.OAuthAuthorizationSessionStatus{
			Phase: platformv1alpha1.OAuthAuthorizationSessionPhaseAwaitingUser,
		},
	}
	if err := client.Create(context.Background(), resource); err != nil {
		t.Fatalf("Create(session) error = %v", err)
	}
	if err := client.Status().Update(context.Background(), resource); err != nil {
		t.Fatalf("Status().Update(session) error = %v", err)
	}
	recordedAt := time.Date(2026, 4, 23, 10, 30, 0, 0, time.UTC)
	manager, err := NewSessionManager(SessionManagerConfig{
		Client:       client,
		Reader:       client,
		Namespace:    "code-code",
		Registry:     sessionAuthorizerRegistryStub{code: unexpectedCodeAuthorizer{}},
		CLISupport:   cliSupportReaderStub{},
		SessionStore: store,
		Now:          func() time.Time { return recordedAt.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("NewSessionManager() error = %v", err)
	}
	hookedSessionID := ""
	manager.SetCodeCallbackRecordedHook(func(_ context.Context, sessionID string) {
		hookedSessionID = sessionID
	})

	event, err := manager.RecordCodeCallback(context.Background(), "codex", &OAuthCodeCallbackPayload{
		Code:                "code-1",
		State:               "state-1",
		ProviderRedirectURI: "http://localhost:1455/auth/callback",
		ReceivedAt:          recordedAt,
	})
	if err != nil {
		t.Fatalf("RecordCodeCallback() error = %v", err)
	}

	if event.SessionID != "session-1" {
		t.Fatalf("event.SessionID = %q, want session-1", event.SessionID)
	}
	if !event.RecordedAt.Equal(recordedAt) {
		t.Fatalf("event.RecordedAt = %s, want %s", event.RecordedAt, recordedAt)
	}
	payload, err := store.GetCodeCallback(context.Background(), "codex", "session-1")
	if err != nil {
		t.Fatalf("GetCodeCallback() error = %v", err)
	}
	if payload.Code != "code-1" {
		t.Fatalf("callback code = %q, want code-1", payload.Code)
	}
	current := &platformv1alpha1.OAuthAuthorizationSessionResource{}
	if err := client.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "code-code", Name: "session-1"}, current); err != nil {
		t.Fatalf("Get(session) error = %v", err)
	}
	if got := current.Annotations[OAuthSessionCallbackRecordedAtAnnotation]; got != recordedAt.Format(time.RFC3339) {
		t.Fatalf("callback recorded annotation = %q, want %q", got, recordedAt.Format(time.RFC3339))
	}
	if current.Status.Phase != platformv1alpha1.OAuthAuthorizationSessionPhaseProcessing {
		t.Fatalf("phase = %q, want processing", current.Status.Phase)
	}
	if hookedSessionID != "session-1" {
		t.Fatalf("hooked session id = %q, want session-1", hookedSessionID)
	}
}

type unexpectedCodeAuthorizer struct{}

func (unexpectedCodeAuthorizer) StartAuthorizationSession(context.Context, *credentialcontract.OAuthAuthorizationRequest) (*credentialcontract.OAuthAuthorizationSession, error) {
	panic("unexpected StartAuthorizationSession")
}

func (unexpectedCodeAuthorizer) CompleteAuthorizationSession(context.Context, *credentialcontract.OAuthAuthorizationExchange) (*credentialcontract.OAuthArtifact, error) {
	panic("unexpected CompleteAuthorizationSession")
}
