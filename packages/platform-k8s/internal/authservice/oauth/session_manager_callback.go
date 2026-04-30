package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	clioauth "code-code.internal/platform-k8s/internal/platform/clidefinitions/oauth"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
)

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
