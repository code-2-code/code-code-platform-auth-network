package credentials

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (r *RefreshRunner) refreshCredential(
	ctx context.Context,
	key types.NamespacedName,
	generation int64,
	definition *credentialv1.CredentialDefinition,
	oauth *credentialv1.OAuthMetadata,
	currentStatus *platformv1alpha1.CredentialOAuthStatus,
	refresher OAuthTokenRefresher,
	now time.Time,
) (*EnsureFreshResult, error) {
	credentialID := definition.CredentialId
	logger := r.logger.With("credential_id", credentialID, "cli_id", oauth.CliId)
	observer := r.observer

	values, err := r.material.ReadValues(ctx, credentialID)
	if err != nil {
		logger.Error("oauth refresh runner: read material failed", "error", err)
		updateErr := r.updateOAuthStatus(ctx, key, generation, nil, refreshConditionUpdate(err))
		if updateErr != nil {
			return nil, updateErr
		}
		return ensureFreshResult("failed", false, nil, r.oauthStatusFromDefinition(definition, currentStatus)), err
	}
	expiresAt, _ := expiresAtFromValues(values)
	refreshToken := strings.TrimSpace(values[materialKeyRefreshToken])
	if refreshToken == "" {
		err := fmt.Errorf("refresh_token is missing from credential material")
		logger.Warn("oauth refresh runner: no refresh_token in material, skipping")
		updateErr := r.updateOAuthStatus(ctx, key, generation, nil, refreshConditionUpdate(err))
		if updateErr != nil {
			return nil, updateErr
		}
		return ensureFreshResult("failed", false, expiresAt, r.oauthStatusFromDefinition(definition, currentStatus)), err
	}

	httpClient, err := r.buildHTTPClient(ctx, credentialID)
	if err != nil {
		logger.Warn("oauth refresh runner: build proxy-aware http client failed, using default", "error", err)
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	var result *OAuthRefreshResult
	var lastErr error
	for attempt := 0; attempt < maxRefreshRetries; attempt++ {
		result, err = refresher.Refresh(ctx, httpClient, refreshToken)
		if err == nil {
			break
		}
		lastErr = err
		if refresher.IsNonRetryable(err) {
			logger.Error("oauth refresh runner: non-retryable refresh error", "error", err)
			status := r.oauthStatusFromDefinition(definition, currentStatus)
			next := now.Add(refreshFailureBackoff)
			status.NextRefreshAfter = &metav1.Time{Time: next}
			if observer != nil {
				observer.RecordRefreshAttempt(oauth.CliId, credentialID, "blocked_non_retryable")
			}
			updateErr := r.updateOAuthStatus(ctx, key, generation, status, refreshConditionUpdate(err))
			if updateErr != nil {
				return nil, updateErr
			}
			return ensureFreshResult("failed", false, expiresAt, status), err
		}
		if attempt < maxRefreshRetries-1 {
			backoff := retryBackoffBase * time.Duration(1<<uint(attempt))
			logger.Warn("oauth refresh runner: refresh attempt failed, retrying", "attempt", attempt+1, "backoff", backoff, "error", err)
			select {
			case <-ctx.Done():
				return ensureFreshResult("failed", false, expiresAt, r.oauthStatusFromDefinition(definition, currentStatus)), ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	if result == nil {
		logger.Error("oauth refresh runner: all refresh attempts failed", "error", lastErr)
		status := r.oauthStatusFromDefinition(definition, currentStatus)
		next := now.Add(refreshFailureBackoff)
		status.NextRefreshAfter = &metav1.Time{Time: next}
		if observer != nil {
			observer.RecordRefreshAttempt(oauth.CliId, credentialID, "failed")
		}
		updateErr := r.updateOAuthStatus(ctx, key, generation, status, refreshConditionUpdate(lastErr))
		if updateErr != nil {
			return nil, updateErr
		}
		return ensureFreshResult("failed", false, expiresAt, status), lastErr
	}

	artifact, status, err := r.refreshedOAuthArtifact(
		ctx,
		oauth.CliId,
		values,
		result,
		definition,
		currentStatus,
		now,
		refresher.RefreshLead(),
	)
	if err != nil {
		logger.Error("oauth refresh runner: project refreshed artifact failed", "error", err)
		failedStatus := r.oauthStatusFromDefinition(definition, currentStatus)
		next := now.Add(refreshFailureBackoff)
		failedStatus.NextRefreshAfter = &metav1.Time{Time: next}
		updateErr := r.updateOAuthStatus(ctx, key, generation, failedStatus, refreshConditionUpdate(err))
		if updateErr != nil {
			return nil, updateErr
		}
		return ensureFreshResult("failed", false, expiresAt, failedStatus), err
	}
	if err := r.material.MergeValues(ctx, credentialID, oauthArtifactValues(*artifact)); err != nil {
		logger.Error("oauth refresh runner: update material failed", "error", err)
		updateErr := r.updateOAuthStatus(ctx, key, generation, nil, refreshConditionUpdate(err))
		if updateErr != nil {
			return nil, updateErr
		}
		return ensureFreshResult("failed", false, expiresAt, status), err
	}

	logger.Info("oauth refresh runner: token refreshed", "generation", status.CredentialGeneration, "expires_at", artifact.ExpiresAt)
	if observer != nil {
		observer.RecordRefreshAttempt(oauth.CliId, credentialID, "succeeded")
	}
	if err := r.updateOAuthStatus(ctx, key, generation, status, refreshConditionUpdate(nil)); err != nil {
		return nil, err
	}
	return ensureFreshResult("refreshed", true, artifact.ExpiresAt, status), nil
}

func (r *RefreshRunner) oauthStatusFromDefinition(definition *credentialv1.CredentialDefinition, current *platformv1alpha1.CredentialOAuthStatus) *platformv1alpha1.CredentialOAuthStatus {
	status := &platformv1alpha1.CredentialOAuthStatus{}
	if current != nil {
		copy := *current
		status = &copy
	}
	if definition == nil {
		return status
	}
	// CliID comes from spec; lifecycle fields live exclusively in status.
	if oauth := definition.GetOauthMetadata(); oauth != nil {
		status.CliID = oauth.CliId
	}
	if status.CredentialGeneration == 0 {
		status.CredentialGeneration = 1
	}
	return status
}

func (r *RefreshRunner) updateOAuthStatus(
	ctx context.Context,
	key types.NamespacedName,
	generation int64,
	oauth *platformv1alpha1.CredentialOAuthStatus,
	refreshCondition oauthConditionUpdate,
) error {
	now := metav1.Now()
	return r.store.UpdateStatus(ctx, key.Name, func(current *platformv1alpha1.CredentialDefinitionResource) error {
		if generation == 0 {
			generation = current.Generation
		}
		status := current.Status
		status.ObservedGeneration = generation
		if oauth != nil {
			status.OAuth = oauth
		}
		meta.SetStatusCondition(&status.Conditions, refreshCondition.condition(generation, now))
		current.Status = status
		return nil
	})
}

func refreshConditionUpdate(refreshErr error) oauthConditionUpdate {
	if refreshErr != nil {
		return oauthConditionUpdate{
			conditionType: ConditionOAuthRefreshReady,
			status:        metav1.ConditionFalse,
			reason:        "RefreshFailed",
			message:       refreshErr.Error(),
		}
	}
	return oauthConditionUpdate{
		conditionType: ConditionOAuthRefreshReady,
		status:        metav1.ConditionTrue,
		reason:        "RefreshSucceeded",
		message:       "OAuth credential refresh state is current.",
	}
}

func (u oauthConditionUpdate) condition(generation int64, now metav1.Time) metav1.Condition {
	return metav1.Condition{
		Type:               u.conditionType,
		Status:             u.status,
		Reason:             u.reason,
		Message:            u.message,
		ObservedGeneration: generation,
		LastTransitionTime: now,
	}
}

func (r *RefreshRunner) buildHTTPClient(ctx context.Context, credentialID string) (*http.Client, error) {
	return outboundhttp.NewClientFactory().NewClient(ctx)
}

func oauthArtifactValues(artifact credentialcontract.OAuthArtifact) map[string]string {
	values := map[string]string{
		materialKeyAccessToken: strings.TrimSpace(artifact.AccessToken),
	}
	if artifact.RefreshToken != "" {
		values[materialKeyRefreshToken] = strings.TrimSpace(artifact.RefreshToken)
	}
	if artifact.IDToken != "" {
		values[materialKeyIDToken] = strings.TrimSpace(artifact.IDToken)
	}
	if artifact.TokenResponseJSON != "" {
		values[materialKeyTokenResponse] = strings.TrimSpace(artifact.TokenResponseJSON)
	}
	if artifact.TokenType != "" {
		values[materialKeyTokenType] = strings.TrimSpace(artifact.TokenType)
	}
	if artifact.ExpiresAt != nil {
		values[materialKeyExpiresAt] = artifact.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if artifact.AccountID != "" {
		values[materialKeyAccountID] = strings.TrimSpace(artifact.AccountID)
	}
	if artifact.AccountEmail != "" {
		values[materialKeyAccountEmail] = strings.TrimSpace(artifact.AccountEmail)
	}
	if len(artifact.Scopes) > 0 {
		values[materialKeyScopes] = strings.Join(artifact.Scopes, ",")
	}
	return values
}
