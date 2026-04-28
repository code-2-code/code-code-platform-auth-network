package oauth

import (
	"context"
	"testing"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type sessionGetNotFoundClient struct {
	ctrlclient.Client
	failGet bool
}

func (c *sessionGetNotFoundClient) Get(ctx context.Context, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
	if !c.failGet {
		return c.Client.Get(ctx, key, obj, opts...)
	}
	return apierrors.NewNotFound(
		schema.GroupResource{
			Group:    platformv1alpha1.GroupVersion.Group,
			Resource: "oauthauthorizationsessions",
		},
		key.Name,
	)
}

func TestSessionManagerGetSessionUsesReaderAfterStart(t *testing.T) {
	reader := newOAuthSessionManagerTestClient()
	client := &sessionGetNotFoundClient{Client: reader}
	store, err := NewOAuthSessionStore(client, reader, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	now := time.Date(2026, 4, 18, 14, 0, 0, 0, time.UTC)
	manager, err := NewSessionManager(SessionManagerConfig{
		Client:     client,
		Reader:     reader,
		Namespace:  "code-code",
		CLISupport: cliSupportReaderStub{},
		Registry: sessionAuthorizerRegistryStub{
			device: deviceAuthorizerStub{
				session: &credentialcontract.DeviceAuthorizationSession{
					SessionID:           "session-reader-1",
					AuthorizationURL:    "https://device.example.test/authorize?user_code=WXYZ",
					UserCode:            "WXYZ",
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

	if _, err := manager.StartSession(context.Background(), &credentialv1.OAuthAuthorizationSessionSpec{
		CliId:              "device-cli",
		Flow:               credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_DEVICE,
		TargetCredentialId: "credential-reader-1",
		TargetDisplayName:  "Reader Device CLI",
	}); err != nil {
		t.Fatalf("StartSession() error = %v", err)
	}
	client.failGet = true

	session, err := manager.GetSession(context.Background(), "session-reader-1")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got, want := session.GetStatus().GetUserCode(), "WXYZ"; got != want {
		t.Fatalf("user_code = %q, want %q", got, want)
	}
}
