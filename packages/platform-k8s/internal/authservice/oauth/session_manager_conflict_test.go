package oauth

import (
	"context"
	"fmt"
	"testing"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type statusConflictOnceClient struct {
	ctrlclient.Client
	statusWriter *statusConflictOnceWriter
}

func newStatusConflictOnceClient(base ctrlclient.Client) *statusConflictOnceClient {
	return &statusConflictOnceClient{
		Client: base,
		statusWriter: &statusConflictOnceWriter{
			SubResourceWriter: base.Status(),
			conflictsLeft:     1,
		},
	}
}

func (c *statusConflictOnceClient) Status() ctrlclient.SubResourceWriter {
	return c.statusWriter
}

type statusConflictOnceWriter struct {
	ctrlclient.SubResourceWriter
	conflictsLeft int
}

func (w *statusConflictOnceWriter) Update(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.SubResourceUpdateOption) error {
	if w.conflictsLeft > 0 {
		w.conflictsLeft--
		return apierrors.NewConflict(
			schema.GroupResource{
				Group:    platformv1alpha1.GroupVersion.Group,
				Resource: "oauthauthorizationsessions",
			},
			obj.GetName(),
			fmt.Errorf("conflict"),
		)
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func TestSessionManagerStartSessionRetriesInitialStatusConflict(t *testing.T) {
	client := newStatusConflictOnceClient(newOAuthSessionManagerTestClient())
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	manager, err := NewSessionManager(SessionManagerConfig{
		Client:     client,
		Reader:     client,
		Namespace:  "code-code",
		CLISupport: cliSupportReaderStub{},
		Registry: sessionAuthorizerRegistryStub{
			device: deviceAuthorizerStub{
				session: &credentialcontract.DeviceAuthorizationSession{
					SessionID:           "session-conflict-1",
					AuthorizationURL:    "https://device.example.test/authorize?user_code=ABCD",
					UserCode:            "ABCD",
					PollIntervalSeconds: 5,
					ExpiresAt:           now.Add(15 * time.Minute),
				},
			},
		},
		SessionStore: store,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSessionManager() error = %v", err)
	}

	session, err := manager.StartSession(context.Background(), &credentialv1.OAuthAuthorizationSessionSpec{
		CliId:              "device-cli",
		Flow:               credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_DEVICE,
		TargetCredentialId: "credential-1",
		TargetDisplayName:  "Device CLI",
	})
	if err != nil {
		t.Fatalf("StartSession() error = %v", err)
	}
	if session.GetStatus().GetAuthorizationUrl() != "https://device.example.test/authorize?user_code=ABCD" {
		t.Fatalf("session authorization url = %q, want initial authorization url", session.GetStatus().GetAuthorizationUrl())
	}

	stored, err := manager.GetSession(context.Background(), "session-conflict-1")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got := stored.GetStatus().GetAuthorizationUrl(); got != "https://device.example.test/authorize?user_code=ABCD" {
		t.Fatalf("AuthorizationUrl = %q, want persisted authorization url", got)
	}
	if got := stored.GetStatus().GetPhase(); got != credentialv1.OAuthAuthorizationPhase_O_AUTH_AUTHORIZATION_PHASE_PENDING {
		t.Fatalf("Phase = %q, want pending", got.String())
	}
	if client.statusWriter.conflictsLeft != 0 {
		t.Fatalf("conflictsLeft = %d, want 0", client.statusWriter.conflictsLeft)
	}
}
