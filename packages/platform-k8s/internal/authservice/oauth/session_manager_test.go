package oauth

import (
	"context"
	"fmt"
	"testing"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type sessionAuthorizerRegistryStub struct {
	code   credentialcontract.OAuthAuthorizer
	device credentialcontract.DeviceAuthorizer
}

func (s sessionAuthorizerRegistryStub) CodeFlowAuthorizer(credentialcontract.OAuthCLIID) (credentialcontract.OAuthAuthorizer, error) {
	if s.code == nil {
		return nil, fmt.Errorf("code authorizer is nil")
	}
	return s.code, nil
}

func (s sessionAuthorizerRegistryStub) DeviceFlowAuthorizer(credentialcontract.OAuthCLIID) (credentialcontract.DeviceAuthorizer, error) {
	if s.device == nil {
		return nil, fmt.Errorf("device authorizer is nil")
	}
	return s.device, nil
}

type deviceAuthorizerStub struct {
	session *credentialcontract.DeviceAuthorizationSession
}

type codeAuthorizerStub struct {
	session     *credentialcontract.OAuthAuthorizationSession
	lastRequest *credentialcontract.OAuthAuthorizationRequest
}

func (s *codeAuthorizerStub) StartAuthorizationSession(_ context.Context, request *credentialcontract.OAuthAuthorizationRequest) (*credentialcontract.OAuthAuthorizationSession, error) {
	s.lastRequest = request
	if s.session == nil {
		return nil, fmt.Errorf("session is nil")
	}
	return s.session, nil
}

func (*codeAuthorizerStub) CompleteAuthorizationSession(context.Context, *credentialcontract.OAuthAuthorizationExchange) (*credentialcontract.OAuthArtifact, error) {
	return nil, fmt.Errorf("unexpected complete")
}

type cliSupportReaderStub struct{}

func (cliSupportReaderStub) Get(context.Context, string) (*supportv1.CLI, error) {
	return nil, fmt.Errorf("unexpected cli support lookup")
}

type codeFlowCLISupportReaderStub struct {
	cli *supportv1.CLI
}

func (s codeFlowCLISupportReaderStub) Get(context.Context, string) (*supportv1.CLI, error) {
	if s.cli == nil {
		return nil, fmt.Errorf("cli support is nil")
	}
	return s.cli, nil
}

func (s deviceAuthorizerStub) StartAuthorizationSession(context.Context, *credentialcontract.DeviceAuthorizationRequest) (*credentialcontract.DeviceAuthorizationSession, error) {
	if s.session == nil {
		return nil, fmt.Errorf("session is nil")
	}
	return s.session, nil
}

func (deviceAuthorizerStub) PollAuthorizationSession(context.Context, string) (*credentialcontract.DeviceAuthorizationResult, error) {
	return nil, fmt.Errorf("unexpected poll")
}

func newOAuthSessionManagerTestClient() ctrlclient.Client {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = platformv1alpha1.AddToScheme(scheme)
	return ctrlclientfake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&platformv1alpha1.OAuthAuthorizationSessionResource{}).
		Build()
}

type cancelAfterOAuthSessionCreateClient struct {
	ctrlclient.Client
	cancel       context.CancelFunc
	statusWriter ctrlclient.SubResourceWriter
}

func newCancelAfterOAuthSessionCreateClient(base ctrlclient.Client, cancel context.CancelFunc) *cancelAfterOAuthSessionCreateClient {
	return &cancelAfterOAuthSessionCreateClient{
		Client:       base,
		cancel:       cancel,
		statusWriter: contextAwareStatusWriter{SubResourceWriter: base.Status()},
	}
}

func (c *cancelAfterOAuthSessionCreateClient) Create(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
	if err := c.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}
	if _, ok := obj.(*platformv1alpha1.OAuthAuthorizationSessionResource); ok && c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *cancelAfterOAuthSessionCreateClient) Status() ctrlclient.SubResourceWriter {
	return c.statusWriter
}

type contextAwareStatusWriter struct {
	ctrlclient.SubResourceWriter
}

func (w contextAwareStatusWriter) Update(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.SubResourceUpdateOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func TestSessionManagerStartSessionPersistsInitialStatus(t *testing.T) {
	client := newOAuthSessionManagerTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	manager, err := NewSessionManager(SessionManagerConfig{
		Client:     client,
		Reader:     client,
		Namespace:  "code-code",
		CLISupport: cliSupportReaderStub{},
		Registry: sessionAuthorizerRegistryStub{
			device: deviceAuthorizerStub{
				session: &credentialcontract.DeviceAuthorizationSession{
					SessionID:           "session-1",
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

	_, err = manager.StartSession(context.Background(), &credentialv1.OAuthAuthorizationSessionSpec{
		CliId:              "device-cli",
		Flow:               credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_DEVICE,
		TargetCredentialId: "credential-1",
		TargetDisplayName:  "Device CLI",
	})
	if err != nil {
		t.Fatalf("StartSession() error = %v", err)
	}

	session, err := manager.GetSession(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got := session.GetStatus().GetAuthorizationUrl(); got != "https://device.example.test/authorize?user_code=ABCD" {
		t.Fatalf("AuthorizationUrl = %q, want persisted authorization url", got)
	}
	if got := session.GetStatus().GetUserCode(); got != "ABCD" {
		t.Fatalf("UserCode = %q, want ABCD", got)
	}
	if got := session.GetStatus().GetPhase(); got != credentialv1.OAuthAuthorizationPhase_O_AUTH_AUTHORIZATION_PHASE_PENDING {
		t.Fatalf("Phase = %q, want pending", got.String())
	}
}

func TestSessionManagerStartSessionPersistsInitialStatusAfterCallerCancellation(t *testing.T) {
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	client := newCancelAfterOAuthSessionCreateClient(newOAuthSessionManagerTestClient(), cancelCaller)
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	manager, err := NewSessionManager(SessionManagerConfig{
		Client:     client,
		Reader:     client,
		Namespace:  "code-code",
		CLISupport: cliSupportReaderStub{},
		Registry: sessionAuthorizerRegistryStub{
			device: deviceAuthorizerStub{
				session: &credentialcontract.DeviceAuthorizationSession{
					SessionID:           "session-cancel-1",
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

	_, err = manager.StartSession(callerCtx, &credentialv1.OAuthAuthorizationSessionSpec{
		CliId:              "device-cli",
		Flow:               credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_DEVICE,
		TargetCredentialId: "credential-1",
		TargetDisplayName:  "Device CLI",
	})
	if err != nil {
		t.Fatalf("StartSession() error = %v", err)
	}
	if callerCtx.Err() == nil {
		t.Fatal("caller context is active, want canceled after oauth session create")
	}

	session, err := manager.GetSession(context.Background(), "session-cancel-1")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got := session.GetStatus().GetAuthorizationUrl(); got != "https://device.example.test/authorize?user_code=WXYZ" {
		t.Fatalf("AuthorizationUrl = %q, want persisted authorization url", got)
	}
	if got := session.GetStatus().GetPhase(); got != credentialv1.OAuthAuthorizationPhase_O_AUTH_AUTHORIZATION_PHASE_PENDING {
		t.Fatalf("Phase = %q, want pending", got.String())
	}
}

func TestSessionManagerStartCodeSessionDerivesCallbackContract(t *testing.T) {
	client := newOAuthSessionManagerTestClient()
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	codeAuthorizer := &codeAuthorizerStub{
		session: &credentialcontract.OAuthAuthorizationSession{
			CliID:            "codex",
			SessionID:        "session-code-1",
			AuthorizationURL: "https://auth.openai.com/oauth/authorize?state=state-1",
			ExpiresAt:        now.Add(10 * time.Minute),
		},
	}
	manager, err := NewSessionManager(SessionManagerConfig{
		Client:    client,
		Reader:    client,
		Namespace: "code-code",
		Registry: sessionAuthorizerRegistryStub{
			code: codeAuthorizer,
		},
		CLISupport: codeFlowCLISupportReaderStub{
			cli: &supportv1.CLI{
				CliId: "codex",
				Oauth: &supportv1.OAuthSupport{
					Flow: credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_CODE,
					CodeFlow: &supportv1.OAuthCodeFlow{
						CallbackDelivery: &supportv1.OAuthCallbackDelivery{
							Mode:                  credentialv1.OAuthCallbackMode_O_AUTH_CALLBACK_MODE_LOCALHOST_RELAY,
							CallbackProviderId:    "codex",
							ProviderRedirectUri:   "http://127.0.0.1:1455/auth/callback",
							LocalhostListenHost:   "127.0.0.1",
							LocalhostListenPort:   1455,
							LocalhostCallbackPath: "/auth/callback",
						},
					},
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
		CliId:              "codex",
		Flow:               credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_CODE,
		TargetCredentialId: "credential-1",
		TargetDisplayName:  "Codex Main",
	})
	if err != nil {
		t.Fatalf("StartSession() error = %v", err)
	}
	if codeAuthorizer.lastRequest == nil {
		t.Fatal("code authorizer request = nil, want request")
	}
	if got := codeAuthorizer.lastRequest.ProviderRedirectURI; got != "http://127.0.0.1:1455/auth/callback" {
		t.Fatalf("ProviderRedirectURI = %q, want localhost callback", got)
	}
	if got := session.GetSpec().GetCallbackMode(); got != credentialv1.OAuthCallbackMode_O_AUTH_CALLBACK_MODE_LOCALHOST_RELAY {
		t.Fatalf("CallbackMode = %s, want LOCALHOST_RELAY", got)
	}
	if got := session.GetSpec().GetProviderRedirectUri(); got != "http://127.0.0.1:1455/auth/callback" {
		t.Fatalf("ProviderRedirectUri = %q, want localhost callback", got)
	}
}
