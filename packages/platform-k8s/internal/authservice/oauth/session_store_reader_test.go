package oauth

import (
	"context"
	"testing"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type oauthSessionStoreStaleReadClient struct {
	ctrlclient.Client
}

func (c oauthSessionStoreStaleReadClient) Get(ctx context.Context, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
	return apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, key.Name)
}

func (c oauthSessionStoreStaleReadClient) List(ctx context.Context, list ctrlclient.ObjectList, opts ...ctrlclient.ListOption) error {
	switch typed := list.(type) {
	case *corev1.SecretList:
		typed.Items = nil
	}
	return nil
}

func TestOAuthSessionStoreUsesReaderForReadListAndUpdate(t *testing.T) {
	reader := newOAuthTestClient()
	store, err := NewOAuthSessionStore(oauthSessionStoreStaleReadClient{Client: reader}, reader, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	if err := store.PutCodeSession(context.Background(), &CodeOAuthSession{
		CliID:               "codex",
		SessionID:           "session-reader",
		ProviderRedirectURI: "http://localhost:1455/auth/callback",
		State:               "state-reader",
		CodeVerifier:        "verifier-reader",
		ExpiresAt:           time.Date(2026, 4, 18, 16, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("PutCodeSession() error = %v", err)
	}

	record, err := store.FindCodeSessionByState(context.Background(), "codex", "state-reader")
	if err != nil {
		t.Fatalf("FindCodeSessionByState() error = %v", err)
	}
	if got, want := record.SessionID, "session-reader"; got != want {
		t.Fatalf("session_id = %q, want %q", got, want)
	}

	if _, err := store.GetCodeSession(context.Background(), "codex", "session-reader"); err != nil {
		t.Fatalf("GetCodeSession() error = %v", err)
	}
	if err := store.PutArtifact(context.Background(), "codex", "session-reader", &credentialcontract.OAuthArtifact{
		AccessToken: "access-token-reader",
	}); err != nil {
		t.Fatalf("PutArtifact() error = %v", err)
	}
	artifact, err := store.GetArtifact(context.Background(), "codex", "session-reader")
	if err != nil {
		t.Fatalf("GetArtifact() error = %v", err)
	}
	if got, want := artifact.AccessToken, "access-token-reader"; got != want {
		t.Fatalf("access_token = %q, want %q", got, want)
	}
}
