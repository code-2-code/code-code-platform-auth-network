package oauth

import (
	"context"
	"testing"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestOAuthSessionStoreCodexRoundTrip(t *testing.T) {
	client := newOAuthTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}

	session := &CodeOAuthSession{
		CliID:               "codex",
		SessionID:           "session-1",
		ProviderRedirectURI: "http://localhost:1455/auth/callback",
		State:               "state-1",
		CodeVerifier:        "verifier-1",
		ExpiresAt:           time.Date(2026, 4, 13, 10, 0, 0, 0, time.UTC),
	}
	if err := store.PutCodeSession(context.Background(), session); err != nil {
		t.Fatalf("PutCodeSession() error = %v", err)
	}

	got, err := store.GetCodeSession(context.Background(), "codex", "session-1")
	if err != nil {
		t.Fatalf("GetCodeSession() error = %v", err)
	}
	if got.State != "state-1" {
		t.Fatalf("State = %q, want state-1", got.State)
	}

	if err := store.DeleteCodeSession(context.Background(), "codex", "session-1"); err != nil {
		t.Fatalf("DeleteCodeSession() error = %v", err)
	}
	if _, err := store.GetCodeSession(context.Background(), "codex", "session-1"); err == nil {
		t.Fatal("GetCodeSession() after delete error = nil, want error")
	}
}

func TestOAuthSessionStoreDeviceRoundTrip(t *testing.T) {
	client := newOAuthTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}

	session := &DeviceOAuthSession{
		CliID:               "device-cli",
		SessionID:           "session-1",
		DeviceCode:          "device-code-1",
		CodeVerifier:        "verifier-1",
		PollIntervalSeconds: 5,
		ExpiresAt:           time.Date(2026, 4, 13, 10, 0, 0, 0, time.UTC),
	}
	if err := store.PutDeviceSession(context.Background(), session); err != nil {
		t.Fatalf("PutDeviceSession() error = %v", err)
	}

	got, err := store.GetDeviceSession(context.Background(), "device-cli", "session-1")
	if err != nil {
		t.Fatalf("GetDeviceSession() error = %v", err)
	}
	if got.DeviceCode != "device-code-1" {
		t.Fatalf("DeviceCode = %q, want device-code-1", got.DeviceCode)
	}

	if err := store.DeleteDeviceSession(context.Background(), "device-cli", "session-1"); err != nil {
		t.Fatalf("DeleteDeviceSession() error = %v", err)
	}
	if _, err := store.GetDeviceSession(context.Background(), "device-cli", "session-1"); err == nil {
		t.Fatal("GetDeviceSession() after delete error = nil, want error")
	}
}

func TestOAuthSessionStoreDeleteExpiredSessions(t *testing.T) {
	client := newOAuthTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	if err := store.PutCodeSession(context.Background(), &CodeOAuthSession{
		CliID:               "codex",
		SessionID:           "expired",
		ProviderRedirectURI: "http://localhost:1455/auth/callback",
		State:               "state-1",
		CodeVerifier:        "verifier-1",
		ExpiresAt:           time.Date(2026, 4, 13, 10, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("PutCodeSession() error = %v", err)
	}
	if err := store.PutDeviceSession(context.Background(), &DeviceOAuthSession{
		CliID:               "device-cli",
		SessionID:           "active",
		DeviceCode:          "device-code-1",
		CodeVerifier:        "verifier-1",
		PollIntervalSeconds: 5,
		ExpiresAt:           time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("PutDeviceSession() error = %v", err)
	}

	if err := store.DeleteExpiredSessions(context.Background(), time.Date(2026, 4, 13, 11, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("DeleteExpiredSessions() error = %v", err)
	}
	if _, err := store.GetCodeSession(context.Background(), "codex", "expired"); err == nil {
		t.Fatal("GetCodeSession() for expired session error = nil, want error")
	}
	if _, err := store.GetDeviceSession(context.Background(), "device-cli", "active"); err != nil {
		t.Fatalf("GetDeviceSession() for active session error = %v", err)
	}
}

func TestOAuthSessionStoreArtifactRoundTrip(t *testing.T) {
	client := newOAuthTestClient()
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
		ExpiresAt:           time.Date(2026, 4, 13, 10, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("PutCodeSession() error = %v", err)
	}
	if err := store.PutArtifact(context.Background(), "codex", "session-1", &credentialcontract.OAuthArtifact{
		AccessToken:       "access-token",
		TokenResponseJSON: `{"scope":"model.read"}`,
	}); err != nil {
		t.Fatalf("PutArtifact() error = %v", err)
	}

	artifact, err := store.GetArtifact(context.Background(), "codex", "session-1")
	if err != nil {
		t.Fatalf("GetArtifact() error = %v", err)
	}
	if got, want := artifact.TokenResponseJSON, `{"scope":"model.read"}`; got != want {
		t.Fatalf("TokenResponseJSON = %q, want %q", got, want)
	}
}

func newOAuthTestClient() ctrlclient.Client {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return ctrlclientfake.NewClientBuilder().WithScheme(scheme).Build()
}
