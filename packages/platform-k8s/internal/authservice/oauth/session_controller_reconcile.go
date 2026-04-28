package oauth

import (
	"context"
	"fmt"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (r *SessionReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	if request.Namespace != r.namespace {
		return ctrl.Result{}, nil
	}
	resource, err := r.resourceStore.Get(ctx, request.Name)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if resource.DeletionTimestamp != nil {
		return ctrl.Result{}, r.finalizeSession(ctx, resource)
	}
	if !containsString(resource.Finalizers, OAuthSessionFinalizer) {
		return ctrl.Result{}, r.resourceStore.Update(ctx, request.Name, func(current *platformv1alpha1.OAuthAuthorizationSessionResource) error {
			current.Finalizers = append(current.Finalizers, OAuthSessionFinalizer)
			return nil
		})
	}
	if resource.Status.Phase == "" {
		return ctrl.Result{}, nil
	}
	if isTerminalPhase(resource.Status.Phase) {
		return r.reconcileTerminal(ctx, resource)
	}
	if resource.Status.ExpiresAt != nil && r.now().UTC().After(resource.Status.ExpiresAt.UTC()) {
		return ctrl.Result{}, r.markTerminal(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseExpired, "OAuth session expired.", "Expired")
	}
	switch resource.Spec.Flow {
	case platformv1alpha1.OAuthAuthorizationSessionFlowCode:
		return r.reconcileCodeFlow(ctx, resource)
	case platformv1alpha1.OAuthAuthorizationSessionFlowDevice:
		return r.reconcileDeviceFlow(ctx, resource)
	default:
		return ctrl.Result{}, r.markTerminal(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseFailed, "Unsupported OAuth flow.", "InvalidSpec")
	}
}

func (r *SessionReconciler) reconcileCodeFlow(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource) (ctrl.Result, error) {
	if resource.Status.Phase == platformv1alpha1.OAuthAuthorizationSessionPhaseAwaitingUser {
		if _, err := r.sessionStore.GetCodeCallback(ctx, resource.Spec.CliID, resource.Spec.SessionID); err != nil {
			return ctrl.Result{}, nil
		}
	}
	if err := r.updateProcessing(ctx, resource, "Authorization received. Exchanging token."); err != nil {
		return ctrl.Result{}, err
	}
	artifact, err := r.executor.ExchangeCode(ctx, resource)
	if err != nil {
		return ctrl.Result{}, r.markTerminal(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseFailed, err.Error(), "ExchangeFailed")
	}
	if err := r.updateProcessing(ctx, resource, "Token received. Importing credential."); err != nil {
		return ctrl.Result{}, err
	}
	imported, err := r.executor.ImportCredential(ctx, resource, artifact)
	if err != nil {
		return ctrl.Result{}, r.markTerminal(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseFailed, err.Error(), "ImportFailed")
	}
	return ctrl.Result{}, r.markSucceeded(ctx, resource, imported)
}

func (r *SessionReconciler) reconcileDeviceFlow(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource) (ctrl.Result, error) {
	if err := r.updateAwaitingUser(ctx, resource, "Waiting for device authorization."); err != nil {
		return ctrl.Result{}, err
	}
	result, err := r.executor.PollDevice(ctx, resource)
	if err != nil {
		return ctrl.Result{}, r.markTerminal(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseFailed, err.Error(), "PollFailed")
	}
	switch result.Status {
	case credentialcontract.DeviceAuthorizationStatusPending:
		return ctrl.Result{RequeueAfter: pollIntervalDuration(result.PollIntervalSeconds, resource.Status.PollIntervalSeconds)}, r.updatePollInterval(ctx, resource, result.PollIntervalSeconds)
	case credentialcontract.DeviceAuthorizationStatusAuthorized:
		if err := r.updateProcessing(ctx, resource, "Authorization received. Importing credential."); err != nil {
			return ctrl.Result{}, err
		}
		imported, importErr := r.executor.ImportCredential(ctx, resource, result.Artifact)
		if importErr != nil {
			return ctrl.Result{}, r.markTerminal(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseFailed, importErr.Error(), "ImportFailed")
		}
		return ctrl.Result{}, r.markSucceeded(ctx, resource, imported)
	case credentialcontract.DeviceAuthorizationStatusExpired:
		return ctrl.Result{}, r.markTerminal(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseExpired, "OAuth session expired.", "Expired")
	case credentialcontract.DeviceAuthorizationStatusDenied:
		return ctrl.Result{}, r.markTerminal(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseFailed, "OAuth device authorization denied.", "Denied")
	default:
		return ctrl.Result{}, r.markTerminal(ctx, resource, platformv1alpha1.OAuthAuthorizationSessionPhaseFailed, fmt.Sprintf("Unexpected device authorization status %q.", result.Status), "PollFailed")
	}
}

func (r *SessionReconciler) reconcileTerminal(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource) (ctrl.Result, error) {
	now := r.now().UTC()
	if retainUntil, ok := parseAnnotationTime(resource.Annotations[OAuthSessionRetainUntilAnnotation]); ok && now.After(retainUntil) {
		if err := r.resourceStore.Delete(ctx, resource.Name); err != nil && !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *SessionReconciler) finalizeSession(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource) error {
	switch resource.Spec.Flow {
	case platformv1alpha1.OAuthAuthorizationSessionFlowCode:
		if err := r.sessionStore.DeleteCodeSession(ctx, resource.Spec.CliID, resource.Spec.SessionID); err != nil {
			return err
		}
	case platformv1alpha1.OAuthAuthorizationSessionFlowDevice:
		if err := r.sessionStore.DeleteDeviceSession(ctx, resource.Spec.CliID, resource.Spec.SessionID); err != nil {
			return err
		}
	}
	return r.resourceStore.Update(ctx, resource.Name, func(current *platformv1alpha1.OAuthAuthorizationSessionResource) error {
		current.Finalizers = removeString(current.Finalizers, OAuthSessionFinalizer)
		return nil
	})
}

func (r *SessionReconciler) observeTerminal(resource *platformv1alpha1.OAuthAuthorizationSessionResource, phase platformv1alpha1.OAuthAuthorizationSessionPhase, completedAt time.Time) {
	if r.observer == nil {
		return
	}
	r.observer.RecordSessionTerminal(resource.Spec.CliID, resource.Spec.Flow, phase, resource.CreationTimestamp.Time.UTC(), completedAt.UTC())
}

func pollIntervalDuration(next, fallback int32) time.Duration {
	seconds := next
	if seconds <= 0 {
		seconds = fallback
	}
	if seconds <= 0 {
		seconds = 5
	}
	return time.Duration(seconds) * time.Second
}
