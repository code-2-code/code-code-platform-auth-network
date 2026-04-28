package oauth

import (
	"context"
	"time"

	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (r *SessionReconciler) updateAwaitingUser(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource, message string) error {
	return r.updatePhase(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseAwaitingUser, message, nil, resource.Status.PollIntervalSeconds, nil, "")
}

func (r *SessionReconciler) updateProcessing(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource, message string) error {
	return r.updatePhase(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseProcessing, message, nil, resource.Status.PollIntervalSeconds, nil, "")
}

func (r *SessionReconciler) updatePollInterval(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource, pollInterval int32) error {
	return r.updatePhase(ctx, resource, resource.Status.Phase, resource.Status.Message, nil, pollInterval, nil, "")
}

func (r *SessionReconciler) markSucceeded(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource, imported *platformv1alpha1.ImportedCredentialSummary) error {
	now := r.now().UTC()
	if err := r.updatePhase(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseSucceeded, "OAuth session completed.", imported, resource.Status.PollIntervalSeconds, &now, "Completed"); err != nil {
		return err
	}
	r.observeTerminal(resource, platformv1alpha1.OAuthAuthorizationSessionPhaseSucceeded, now)
	return nil
}

func (r *SessionReconciler) markTerminal(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource, phase platformv1alpha1.OAuthAuthorizationSessionPhase, message string, reason string) error {
	now := r.now().UTC()
	if err := r.updatePhase(ctx, resource, phase, message, nil, resource.Status.PollIntervalSeconds, &now, reason); err != nil {
		return err
	}
	r.observeTerminal(resource, phase, now)
	return nil
}

func (r *SessionReconciler) updatePhase(
	ctx context.Context,
	resource *platformv1alpha1.OAuthAuthorizationSessionResource,
	phase platformv1alpha1.OAuthAuthorizationSessionPhase,
	message string,
	imported *platformv1alpha1.ImportedCredentialSummary,
	pollInterval int32,
	terminalNow *time.Time,
	reason string,
) error {
	key := types.NamespacedName{Namespace: resource.Namespace, Name: resource.Name}
	if terminalNow != nil {
		if err := r.resourceStore.Update(ctx, key.Name, func(current *platformv1alpha1.OAuthAuthorizationSessionResource) error {
			if current.Annotations == nil {
				current.Annotations = map[string]string{}
			}
			current.Annotations[OAuthSessionRetainUntilAnnotation] = newTerminalAnnotationTime(terminalNow.UTC(), r.terminalRetention)
			return nil
		}); err != nil {
			return err
		}
	}
	return r.resourceStore.UpdateStatus(ctx, key.Name, func(current *platformv1alpha1.OAuthAuthorizationSessionResource) error {
		now := metav1.NewTime(r.now().UTC())
		current.Status.Phase = phase
		current.Status.Message = message
		current.Status.PollIntervalSeconds = pollInterval
		current.Status.UpdatedAt = &now
		current.Status.ObservedGeneration = current.Generation
		if imported != nil {
			current.Status.ImportedCredential = imported
		}
		if reason != "" {
			meta.SetStatusCondition(&current.Status.Conditions, metav1.Condition{
				Type:               ConditionOAuthCompleted,
				Status:             metav1.ConditionTrue,
				Reason:             reason,
				Message:            message,
				ObservedGeneration: current.Generation,
				LastTransitionTime: now,
			})
		}
		return nil
	})
}
