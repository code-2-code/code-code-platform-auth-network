package credentials

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
	clisupport "code-code.internal/platform-k8s/internal/supportservice/clidefinitions/support"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	refreshFailureBackoff = 5 * time.Minute
	maxRefreshRetries     = 3
	retryBackoffBase      = 2 * time.Second

	ConditionOAuthRefreshReady = "OAuthRefreshReady"
)

type oauthConditionUpdate struct {
	conditionType string
	status        metav1.ConditionStatus
	reason        string
	message       string
}

type refreshAttemptRecorder interface {
	RecordRefreshAttempt(cliID, credentialID, result string)
}

// RefreshRunner scans OAuth credentials and refreshes tokens that are near expiry.
type RefreshRunner struct {
	client     ctrlclient.Client
	namespace  string
	store      ResourceStore
	material   CredentialMaterialStore
	refreshers map[string]OAuthTokenRefresher
	cliSupport *clisupport.ManagementService
	observer   refreshAttemptRecorder
	logger     *slog.Logger
}

// RefreshRunnerConfig groups dependencies for the RefreshRunner.
type RefreshRunnerConfig struct {
	Client     ctrlclient.Client
	Namespace  string
	Store      ResourceStore
	Material   CredentialMaterialStore
	Refreshers []OAuthTokenRefresher
	Observer   refreshAttemptRecorder
	Logger     *slog.Logger
}

// EnsureFreshResult describes one ensure-fresh execution outcome.
type EnsureFreshResult struct {
	Outcome          string
	Refreshed        bool
	ExpiresAt        *time.Time
	NextRefreshAfter *time.Time
	LastRefreshedAt  *time.Time
}

// NewRefreshRunner creates one OAuth refresh runner.
func NewRefreshRunner(config RefreshRunnerConfig) (*RefreshRunner, error) {
	if config.Client == nil {
		return nil, fmt.Errorf("credentials: refresh runner client is nil")
	}
	if config.Namespace == "" {
		return nil, fmt.Errorf("credentials: refresh runner namespace is empty")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if len(config.Refreshers) == 0 {
		config.Refreshers = DefaultOAuthTokenRefreshers()
	}
	cliSupport, err := clisupport.NewManagementService()
	if err != nil {
		return nil, err
	}
	store := config.Store
	if store == nil {
		store, err = NewKubernetesResourceStore(config.Client, config.Namespace)
		if err != nil {
			return nil, err
		}
	}
	materialStore := config.Material
	if materialStore == nil {
		return nil, fmt.Errorf("credentials: refresh runner material store is nil")
	}
	refreshers := make(map[string]OAuthTokenRefresher, len(config.Refreshers))
	for _, r := range config.Refreshers {
		cliID := strings.TrimSpace(r.CliID())
		if cliID == "" {
			continue
		}
		refreshers[cliID] = r
	}
	return &RefreshRunner{
		client:     config.Client,
		namespace:  config.Namespace,
		store:      store,
		material:   materialStore,
		refreshers: refreshers,
		cliSupport: cliSupport,
		observer:   config.Observer,
		logger:     config.Logger,
	}, nil
}

// RunAll refreshes all OAuth credentials that are within the configured refresh window.
func (r *RefreshRunner) RunAll(ctx context.Context) error {
	now := time.Now().UTC()

	items, err := r.store.List(ctx)
	if err != nil {
		return fmt.Errorf("credentials: list credential definitions: %w", err)
	}

	slices.SortFunc(items, func(a, b platformv1alpha1.CredentialDefinitionResource) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	})

	var errs []error
	for i := range items {
		if _, err := r.runOne(ctx, &items[i], now, runOneOptions{}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *RefreshRunner) runOne(ctx context.Context, resource *platformv1alpha1.CredentialDefinitionResource, now time.Time, options runOneOptions) (*EnsureFreshResult, error) {
	if resource == nil || resource.DeletionTimestamp != nil || resource.Spec.Definition == nil {
		return &EnsureFreshResult{Outcome: "fresh"}, nil
	}
	definition := resource.Spec.Definition
	if definition.CredentialId == "" {
		definition.CredentialId = resource.Name
	}
	if definition.Kind != credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH {
		return &EnsureFreshResult{Outcome: "fresh"}, nil
	}

	oauth := definition.GetOauthMetadata()
	key := types.NamespacedName{Namespace: resource.Namespace, Name: resource.Name}
	if oauth == nil || oauth.CliId == "" {
		err := fmt.Errorf("oauth metadata and cli_id are required")
		updateErr := r.updateOAuthStatus(ctx, key, resource.Generation, nil, refreshConditionUpdate(err))
		if updateErr != nil {
			return nil, updateErr
		}
		if options.strict {
			return nil, err
		}
		return &EnsureFreshResult{Outcome: "fresh"}, nil
	}
	refresher, ok := r.refreshers[oauth.CliId]
	if !ok {
		err := fmt.Errorf("oauth refresher %q is not registered", oauth.CliId)
		updateErr := r.updateOAuthStatus(ctx, key, resource.Generation, nil, refreshConditionUpdate(err))
		if updateErr != nil {
			return nil, updateErr
		}
		if options.strict {
			return nil, err
		}
		return &EnsureFreshResult{Outcome: "fresh"}, nil
	}

	values, err := r.material.ReadValues(ctx, definition.CredentialId)
	if err != nil {
		updateErr := r.updateOAuthStatus(ctx, key, resource.Generation, nil, refreshConditionUpdate(err))
		if updateErr != nil {
			return nil, updateErr
		}
		if options.strict {
			return nil, err
		}
		return &EnsureFreshResult{Outcome: "fresh"}, nil
	}

	expiresAt, needs, nextRefreshAfter, scheduleErr := r.evaluateRefresh(values, resource.Status.OAuth, refresher, now, options)
	if scheduleErr != nil {
		updateErr := r.updateOAuthStatus(ctx, key, resource.Generation, nil, refreshConditionUpdate(scheduleErr))
		if updateErr != nil {
			return nil, updateErr
		}
		if options.strict {
			return nil, scheduleErr
		}
		return &EnsureFreshResult{Outcome: "fresh", ExpiresAt: expiresAt}, nil
	}

	if !needs {
		status := r.oauthStatusFromDefinition(definition, resource.Status.OAuth)
		if nextRefreshAfter != nil {
			status.NextRefreshAfter = &metav1.Time{Time: *nextRefreshAfter}
		}
		if err := r.updateOAuthStatus(ctx, key, resource.Generation, status, refreshConditionUpdate(nil)); err != nil {
			return nil, err
		}
		return &EnsureFreshResult{
			Outcome:          "fresh",
			Refreshed:        false,
			ExpiresAt:        expiresAt,
			NextRefreshAfter: nextRefreshAfter,
			LastRefreshedAt:  timePointerFromMeta(status.LastRefreshedAt),
		}, nil
	}

	result, err := r.refreshCredential(ctx, key, resource.Generation, definition, oauth, resource.Status.OAuth, refresher, now)
	if err != nil && !options.strict {
		return result, nil
	}
	return result, err
}

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

func nextOAuthRefreshAfter(
	expiresAt *time.Time,
	refreshWindow time.Duration,
) *time.Time {
	if expiresAt == nil {
		return nil
	}
	if refreshWindow <= 0 {
		refreshWindow = time.Minute
	}
	candidate := expiresAt.Add(-refreshWindow).UTC()
	return &candidate
}

func expiresAtFromValues(values map[string]string) (*time.Time, error) {
	raw := strings.TrimSpace(values[materialKeyExpiresAt])
	if raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("parse credential material expires_at: %w", err)
	}
	value := parsed.UTC()
	return &value, nil
}

// ExpiresAtFromMaterialValues returns the OAuth expiry encoded in credential
// material values.
func ExpiresAtFromMaterialValues(values map[string]string) (*time.Time, error) {
	return expiresAtFromValues(values)
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

func ensureFreshResult(
	outcome string,
	refreshed bool,
	expiresAt *time.Time,
	status *platformv1alpha1.CredentialOAuthStatus,
) *EnsureFreshResult {
	result := &EnsureFreshResult{
		Outcome:   outcome,
		Refreshed: refreshed,
		ExpiresAt: timePointerCopy(expiresAt),
	}
	if status == nil {
		return result
	}
	result.NextRefreshAfter = timePointerFromMeta(status.NextRefreshAfter)
	result.LastRefreshedAt = timePointerFromMeta(status.LastRefreshedAt)
	return result
}

func timePointerFromMeta(value *metav1.Time) *time.Time {
	if value == nil {
		return nil
	}
	parsed := value.Time.UTC()
	return &parsed
}

func timePointerCopy(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}
