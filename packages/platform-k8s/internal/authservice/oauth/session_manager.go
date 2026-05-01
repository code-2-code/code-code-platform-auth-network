package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type sessionAuthorizerRegistry interface {
	CodeFlowAuthorizer(cli credentialcontract.OAuthCLIID) (credentialcontract.OAuthAuthorizer, error)
	DeviceFlowAuthorizer(cli credentialcontract.OAuthCLIID) (credentialcontract.DeviceAuthorizer, error)
}

type cliOAuthReader interface {
	Get(ctx context.Context, cliID string) (*supportv1.CLI, error)
}

type SessionObserver interface {
	RecordSessionStarted(cliID string, flow credentialv1.OAuthAuthorizationFlow)
	RecordSessionTerminal(cliID string, flow platformv1alpha1.OAuthAuthorizationSessionFlow, phase platformv1alpha1.OAuthAuthorizationSessionPhase, startedAt, endedAt time.Time)
}

const startSessionPersistenceTimeout = 30 * time.Second

// SessionManager manages OAuthAuthorizationSession resources and callback payloads.
type SessionManager struct {
	client                ctrlclient.Client
	reader                ctrlclient.Reader
	namespace             string
	resourceStore         AuthorizationSessionResourceStore
	registry              sessionAuthorizerRegistry
	cliSupport            cliOAuthReader
	hostedCallbackBaseURL string
	sessionStore          *OAuthSessionSecretStore
	observer              SessionObserver
	now                   func() time.Time
	codeCallbackRecorded  func(context.Context, string)
}

// SessionManagerConfig groups SessionManager dependencies.
type SessionManagerConfig struct {
	Client                ctrlclient.Client
	Reader                ctrlclient.Reader
	Namespace             string
	ResourceStore         AuthorizationSessionResourceStore
	Registry              sessionAuthorizerRegistry
	CLISupport            cliOAuthReader
	HostedCallbackBaseURL string
	SessionStore          *OAuthSessionSecretStore
	Observer              SessionObserver
	Now                   func() time.Time
}

// NewSessionManager creates one OAuth session manager.
func NewSessionManager(config SessionManagerConfig) (*SessionManager, error) {
	if config.Client == nil {
		return nil, fmt.Errorf("platformk8s/oauth: session manager client is nil")
	}
	if strings.TrimSpace(config.Namespace) == "" {
		return nil, fmt.Errorf("platformk8s/oauth: session manager namespace is empty")
	}
	if config.Reader == nil {
		return nil, fmt.Errorf("platformk8s/oauth: session manager reader is nil")
	}
	if config.Registry == nil {
		return nil, fmt.Errorf("platformk8s/oauth: session manager registry is nil")
	}
	if config.CLISupport == nil {
		return nil, fmt.Errorf("platformk8s/oauth: session manager cli support reader is nil")
	}
	if config.SessionStore == nil {
		return nil, fmt.Errorf("platformk8s/oauth: session manager secret store is nil")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	resourceStore := config.ResourceStore
	if resourceStore == nil {
		var err error
		resourceStore, err = NewKubernetesAuthorizationSessionResourceStore(config.Client, config.Reader, config.Namespace)
		if err != nil {
			return nil, err
		}
	}
	return &SessionManager{
		client:                config.Client,
		reader:                config.Reader,
		namespace:             strings.TrimSpace(config.Namespace),
		resourceStore:         resourceStore,
		registry:              config.Registry,
		cliSupport:            config.CLISupport,
		hostedCallbackBaseURL: strings.TrimSpace(config.HostedCallbackBaseURL),
		sessionStore:          config.SessionStore,
		observer:              config.Observer,
		now:                   config.Now,
	}, nil
}

// StartSession starts one OAuth session and persists the resource.
func (m *SessionManager) StartSession(ctx context.Context, request *credentialv1.OAuthAuthorizationSessionSpec) (*credentialv1.OAuthAuthorizationSessionState, error) {
	if request == nil {
		return nil, fmt.Errorf("platformk8s/oauth: start session request is nil")
	}
	now := metav1.NewTime(m.now().UTC())
	resource, err := m.startResource(ctx, request, now)
	if err != nil {
		return nil, err
	}
	state := sessionStateFromResource(resource.DeepCopyObject().(*platformv1alpha1.OAuthAuthorizationSessionResource))
	status := resource.Status
	resource.Status = platformv1alpha1.OAuthAuthorizationSessionStatus{}
	persistCtx, cancelPersistence := startSessionPersistenceContext(ctx)
	defer cancelPersistence()
	if err := m.resourceStore.Create(persistCtx, resource); err != nil {
		return nil, fmt.Errorf("platformk8s/oauth: create oauth session %q: %w", resource.Name, err)
	}
	if err := m.initializeStatus(persistCtx, resource, status); err != nil {
		cleanupCtx, cancelCleanup := startSessionPersistenceContext(context.Background())
		defer cancelCleanup()
		_ = m.resourceStore.Delete(cleanupCtx, resource.Name)
		return nil, err
	}
	if m.observer != nil {
		m.observer.RecordSessionStarted(request.GetCliId(), request.GetFlow())
	}
	return state, nil
}

func startSessionPersistenceContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), startSessionPersistenceTimeout)
}

func (m *SessionManager) initializeStatus(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource, status platformv1alpha1.OAuthAuthorizationSessionStatus) error {
	if resource == nil {
		return fmt.Errorf("platformk8s/oauth: oauth session resource is nil")
	}
	key := types.NamespacedName{Namespace: resource.Namespace, Name: resource.Name}
	if err := m.updateSessionStatus(ctx, key, func(current *platformv1alpha1.OAuthAuthorizationSessionResource) error {
		applyInitialStatus(current, status)
		return nil
	}); err != nil {
		return fmt.Errorf("platformk8s/oauth: initialize oauth session %q status: %w", resource.Name, err)
	}
	return nil
}

func applyInitialStatus(current *platformv1alpha1.OAuthAuthorizationSessionResource, status platformv1alpha1.OAuthAuthorizationSessionStatus) {
	current.Status.Phase = status.Phase
	current.Status.AuthorizationURL = status.AuthorizationURL
	current.Status.UserCode = status.UserCode
	current.Status.PollIntervalSeconds = status.PollIntervalSeconds
	current.Status.Message = status.Message
	current.Status.ImportedCredential = status.ImportedCredential
	current.Status.ObservedGeneration = current.Generation
	current.Status.Conditions = append([]metav1.Condition(nil), status.Conditions...)
	if status.ExpiresAt != nil {
		current.Status.ExpiresAt = status.ExpiresAt.DeepCopy()
	} else {
		current.Status.ExpiresAt = nil
	}
	if status.UpdatedAt != nil {
		current.Status.UpdatedAt = status.UpdatedAt.DeepCopy()
	} else {
		current.Status.UpdatedAt = nil
	}
}

func errUnsupportedFlow(flow credentialv1.OAuthAuthorizationFlow) error {
	return fmt.Errorf("platformk8s/oauth: unsupported oauth flow %q", flow.String())
}


// GetSession returns one OAuth session state.
func (m *SessionManager) GetSession(ctx context.Context, sessionID string) (*credentialv1.OAuthAuthorizationSessionState, error) {
	resource, err := m.resourceStore.Get(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/oauth: get oauth session %q: %w", sessionID, err)
	}
	return sessionStateFromResource(resource), nil
}

// GetArtifact returns the stored OAuth artifact for one CLI session.
func (m *SessionManager) GetArtifact(ctx context.Context, cliID, sessionID string) (*credentialcontract.OAuthArtifact, error) {
	if m == nil || m.sessionStore == nil {
		return nil, fmt.Errorf("platformk8s/oauth: session manager secret store is not initialized")
	}
	return m.sessionStore.GetArtifact(ctx, strings.TrimSpace(cliID), strings.TrimSpace(sessionID))
}
