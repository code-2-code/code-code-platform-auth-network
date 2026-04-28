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
	clioauth "code-code.internal/platform-k8s/internal/supportservice/clidefinitions/oauth"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type sessionAuthorizerRegistry interface {
	CodeFlowAuthorizer(cli credentialcontract.OAuthCLIID) (credentialcontract.OAuthAuthorizer, error)
	DeviceFlowAuthorizer(cli credentialcontract.OAuthCLIID) (credentialcontract.DeviceAuthorizer, error)
}

type cliOAuthSupportReader interface {
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
	cliSupport            cliOAuthSupportReader
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
	CLISupport            cliOAuthSupportReader
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

func (m *SessionManager) startResource(ctx context.Context, request *credentialv1.OAuthAuthorizationSessionSpec, now metav1.Time) (*platformv1alpha1.OAuthAuthorizationSessionResource, error) {
	cliID := strings.TrimSpace(request.GetCliId())
	oauthSurface := credentialcontract.OAuthCLIID(cliID)
	switch request.GetFlow() {
	case credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_CODE:
		callbackContract, err := m.resolveCodeFlowCallbackContract(ctx, cliID)
		if err != nil {
			return nil, err
		}
		authorizer, err := m.registry.CodeFlowAuthorizer(oauthSurface)
		if err != nil {
			return nil, err
		}
		session, err := authorizer.StartAuthorizationSession(ctx, &credentialcontract.OAuthAuthorizationRequest{
			CliID:               oauthSurface,
			ProviderRedirectURI: callbackContract.ProviderRedirectURI,
		})
		if err != nil {
			return nil, err
		}
		return &platformv1alpha1.OAuthAuthorizationSessionResource{
			TypeMeta: metav1.TypeMeta{
				APIVersion: platformv1alpha1.GroupVersion.String(),
				Kind:       platformv1alpha1.KindOAuthAuthorizationSessionResource,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       session.SessionID,
				Namespace:  m.namespace,
				Finalizers: []string{OAuthSessionFinalizer},
			},
			Spec: platformv1alpha1.OAuthAuthorizationSessionSpec{
				SessionID:           session.SessionID,
				CliID:               cliID,
				Flow:                platformv1alpha1.OAuthAuthorizationSessionFlowCode,
				CallbackMode:        fromProtoCallbackMode(callbackContract.Mode),
				ProviderRedirectURI: callbackContract.ProviderRedirectURI,
				TargetCredentialID:  strings.TrimSpace(request.GetTargetCredentialId()),
				TargetDisplayName:   strings.TrimSpace(request.GetTargetDisplayName()),
			},
			Status: platformv1alpha1.OAuthAuthorizationSessionStatus{
				CommonStatusFields: platformv1alpha1.CommonStatusFields{
					Conditions: []metav1.Condition{{
						Type:               ConditionOAuthAccepted,
						Status:             metav1.ConditionTrue,
						Reason:             "Accepted",
						Message:            "OAuth session accepted.",
						ObservedGeneration: 1,
						LastTransitionTime: now,
					}, {
						Type:               ConditionOAuthAuthorizationReady,
						Status:             metav1.ConditionTrue,
						Reason:             "AuthorizationReady",
						Message:            "Authorization URL is ready.",
						ObservedGeneration: 1,
						LastTransitionTime: now,
					}},
				},
				Phase:            platformv1alpha1.OAuthAuthorizationSessionPhaseAwaitingUser,
				AuthorizationURL: session.AuthorizationURL,
				ExpiresAt:        toMetaTime(session.ExpiresAt),
				UpdatedAt:        &now,
			},
		}, nil
	case credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_DEVICE:
		authorizer, err := m.registry.DeviceFlowAuthorizer(oauthSurface)
		if err != nil {
			return nil, err
		}
		session, err := authorizer.StartAuthorizationSession(ctx, &credentialcontract.DeviceAuthorizationRequest{})
		if err != nil {
			return nil, err
		}
		return &platformv1alpha1.OAuthAuthorizationSessionResource{
			TypeMeta: metav1.TypeMeta{
				APIVersion: platformv1alpha1.GroupVersion.String(),
				Kind:       platformv1alpha1.KindOAuthAuthorizationSessionResource,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       session.SessionID,
				Namespace:  m.namespace,
				Finalizers: []string{OAuthSessionFinalizer},
			},
			Spec: platformv1alpha1.OAuthAuthorizationSessionSpec{
				SessionID:          session.SessionID,
				CliID:              cliID,
				Flow:               platformv1alpha1.OAuthAuthorizationSessionFlowDevice,
				TargetCredentialID: strings.TrimSpace(request.GetTargetCredentialId()),
				TargetDisplayName:  strings.TrimSpace(request.GetTargetDisplayName()),
			},
			Status: platformv1alpha1.OAuthAuthorizationSessionStatus{
				CommonStatusFields: platformv1alpha1.CommonStatusFields{
					Conditions: []metav1.Condition{{
						Type:               ConditionOAuthAccepted,
						Status:             metav1.ConditionTrue,
						Reason:             "Accepted",
						Message:            "OAuth session accepted.",
						ObservedGeneration: 1,
						LastTransitionTime: now,
					}, {
						Type:               ConditionOAuthAuthorizationReady,
						Status:             metav1.ConditionTrue,
						Reason:             "AuthorizationReady",
						Message:            "Device authorization session is ready.",
						ObservedGeneration: 1,
						LastTransitionTime: now,
					}},
				},
				Phase:               platformv1alpha1.OAuthAuthorizationSessionPhasePending,
				AuthorizationURL:    session.AuthorizationURL,
				UserCode:            session.UserCode,
				PollIntervalSeconds: session.PollIntervalSeconds,
				ExpiresAt:           toMetaTime(session.ExpiresAt),
				UpdatedAt:           &now,
			},
		}, nil
	default:
		return nil, fmt.Errorf("platformk8s/oauth: unsupported oauth flow %q", request.GetFlow().String())
	}
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

// CancelSession deletes one OAuth session after marking it canceled.
func (m *SessionManager) CancelSession(ctx context.Context, sessionID string) (*credentialv1.OAuthAuthorizationSessionState, error) {
	key := types.NamespacedName{Namespace: m.namespace, Name: strings.TrimSpace(sessionID)}
	now := metav1.NewTime(m.now().UTC())
	if err := m.updateSessionStatus(ctx, key, func(current *platformv1alpha1.OAuthAuthorizationSessionResource) error {
		current.Status.Phase = platformv1alpha1.OAuthAuthorizationSessionPhaseCanceled
		current.Status.Message = "OAuth session canceled."
		current.Status.UpdatedAt = &now
		current.Status.ObservedGeneration = current.Generation
		meta.SetStatusCondition(&current.Status.Conditions, metav1.Condition{
			Type:               ConditionOAuthCompleted,
			Status:             metav1.ConditionTrue,
			Reason:             "Canceled",
			Message:            "OAuth session canceled.",
			ObservedGeneration: current.Generation,
			LastTransitionTime: now,
		})
		return nil
	}); err != nil {
		return nil, err
	}
	resource, err := m.resourceStore.Get(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/oauth: read canceled oauth session %q: %w", sessionID, err)
	}
	if m.observer != nil {
		m.observer.RecordSessionTerminal(resource.Spec.CliID, resource.Spec.Flow, platformv1alpha1.OAuthAuthorizationSessionPhaseCanceled, resource.CreationTimestamp.Time.UTC(), now.Time.UTC())
	}
	if err := m.resourceStore.Delete(ctx, resource.Name); err != nil {
		return nil, fmt.Errorf("platformk8s/oauth: delete oauth session %q: %w", sessionID, err)
	}
	return sessionStateFromResource(resource), nil
}

// RecordCodeCallback records one code-flow callback and pokes the controller.
func (m *SessionManager) RecordCodeCallback(ctx context.Context, cliID string, payload *OAuthCodeCallbackPayload) (*CodeCallbackRecordedEvent, error) {
	trimmedCliID := strings.TrimSpace(cliID)
	if trimmedCliID == "" {
		return nil, fmt.Errorf("platformk8s/oauth: callback cli id is empty")
	}
	record, err := m.sessionStore.FindCodeSessionByState(ctx, trimmedCliID, payload.State)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(payload.ProviderRedirectURI) != record.ProviderRedirectURI {
		return nil, fmt.Errorf("platformk8s/oauth: callback provider redirect uri mismatch")
	}
	if err := m.sessionStore.PutCodeCallback(ctx, trimmedCliID, record.SessionID, payload); err != nil {
		return nil, err
	}
	key := types.NamespacedName{Namespace: m.namespace, Name: record.SessionID}
	if err := m.updateSessionResource(ctx, key, func(current *platformv1alpha1.OAuthAuthorizationSessionResource) error {
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		current.Annotations[OAuthSessionCallbackRecordedAtAnnotation] = payload.ReceivedAt.UTC().Format(time.RFC3339)
		return nil
	}); err != nil {
		return nil, err
	}
	if strings.TrimSpace(payload.Error) == "" {
		if err := m.markCallbackProcessing(ctx, key); err != nil {
			return nil, err
		}
	}
	if m.codeCallbackRecorded != nil {
		m.codeCallbackRecorded(ctx, record.SessionID)
	}
	return &CodeCallbackRecordedEvent{
		SessionID:  record.SessionID,
		RecordedAt: payload.ReceivedAt.UTC(),
	}, nil
}

func (m *SessionManager) markCallbackProcessing(ctx context.Context, key types.NamespacedName) error {
	now := metav1.NewTime(m.now().UTC())
	return m.updateSessionStatus(ctx, key, func(current *platformv1alpha1.OAuthAuthorizationSessionResource) error {
		if current.Status.Phase != platformv1alpha1.OAuthAuthorizationSessionPhaseAwaitingUser {
			return nil
		}
		current.Status.Phase = platformv1alpha1.OAuthAuthorizationSessionPhaseProcessing
		current.Status.Message = "Authorization callback received."
		current.Status.UpdatedAt = &now
		current.Status.ObservedGeneration = current.Generation
		return nil
	})
}

func (m *SessionManager) updateSessionStatus(
	ctx context.Context,
	key types.NamespacedName,
	mutate func(*platformv1alpha1.OAuthAuthorizationSessionResource) error,
) error {
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return m.resourceStore.UpdateStatus(ctx, key.Name, func(current *platformv1alpha1.OAuthAuthorizationSessionResource) error {
			if err := mutate(current); err != nil {
				return err
			}
			return nil
		})
	}); err != nil {
		return fmt.Errorf("platformk8s: update status %q: %w", key.String(), err)
	}
	return nil
}

func (m *SessionManager) updateSessionResource(
	ctx context.Context,
	key types.NamespacedName,
	mutate func(*platformv1alpha1.OAuthAuthorizationSessionResource) error,
) error {
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return m.resourceStore.Update(ctx, key.Name, func(current *platformv1alpha1.OAuthAuthorizationSessionResource) error {
			if err := mutate(current); err != nil {
				return err
			}
			return nil
		})
	}); err != nil {
		return fmt.Errorf("platformk8s: update %q: %w", key.String(), err)
	}
	return nil
}

func (m *SessionManager) resolveCodeFlowCallbackContract(ctx context.Context, cliID string) (*clioauth.OAuthCallbackContract, error) {
	if m == nil || m.cliSupport == nil {
		return nil, fmt.Errorf("platformk8s/oauth: session manager cli support reader is not initialized")
	}
	cli, err := m.cliSupport.Get(ctx, strings.TrimSpace(cliID))
	if err != nil {
		return nil, fmt.Errorf("platformk8s/oauth: resolve cli oauth support %q: %w", cliID, err)
	}
	if cli.GetOauth() == nil || cli.GetOauth().GetFlow() != credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_CODE {
		return nil, fmt.Errorf("platformk8s/oauth: cli %q does not expose oauth code flow", cliID)
	}
	contract, err := clioauth.ResolveOAuthCallbackContract(cli, m.hostedCallbackBaseURL)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/oauth: resolve cli oauth callback contract for %q: %w", cliID, err)
	}
	return contract, nil
}

func toMetaTime(value time.Time) *metav1.Time {
	if value.IsZero() {
		return nil
	}
	next := metav1.NewTime(value.UTC())
	return &next
}
