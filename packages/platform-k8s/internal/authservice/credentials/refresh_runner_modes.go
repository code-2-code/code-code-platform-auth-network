package credentials

import (
	"context"
	"fmt"
	"time"

	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
)

type refreshMode int

const (
	refreshModeScheduled refreshMode = iota
	refreshModeEnsureFresh
)

type runOneOptions struct {
	minTTL       time.Duration
	mode         refreshMode
	strict       bool
	forceRefresh bool
}

func scheduledRunOneOptions() runOneOptions {
	return runOneOptions{mode: refreshModeScheduled}
}

func ensureFreshRunOneOptions(options EnsureFreshOptions) runOneOptions {
	return runOneOptions{
		minTTL:       options.MinTTL,
		mode:         refreshModeEnsureFresh,
		strict:       true,
		forceRefresh: options.ForceRefresh,
	}
}

func (r *RefreshRunner) runCredential(ctx context.Context, credentialID string, options runOneOptions) (*EnsureFreshResult, error) {
	if credentialID == "" {
		return nil, fmt.Errorf("credentials: credential id is empty")
	}
	resource, err := r.store.Get(ctx, credentialID)
	if err != nil {
		return nil, fmt.Errorf("credentials: get credential %q: %w", credentialID, err)
	}
	return r.runOne(ctx, resource, time.Now().UTC(), options)
}

func (r *RefreshRunner) runScheduledCredential(ctx context.Context, credentialID string) (*EnsureFreshResult, error) {
	return r.runCredential(ctx, credentialID, scheduledRunOneOptions())
}

func (r *RefreshRunner) evaluateRefresh(
	values map[string]string,
	currentStatus *platformv1alpha1.CredentialOAuthStatus,
	refresher OAuthTokenRefresher,
	now time.Time,
	options runOneOptions,
) (*time.Time, bool, *time.Time, error) {
	expiresAt, err := expiresAtFromValues(values)
	if err != nil {
		return nil, false, nil, err
	}
	if options.forceRefresh {
		return expiresAt, true, scheduledNextRefreshAfter(currentStatus, refresher, expiresAt), nil
	}
	switch options.mode {
	case refreshModeEnsureFresh:
		return evaluateEnsureFresh(currentStatus, refresher, now, options.minTTL, expiresAt)
	default:
		return evaluateScheduledRefresh(values, currentStatus, refresher, now)
	}
}

func evaluateScheduledRefresh(
	values map[string]string,
	currentStatus *platformv1alpha1.CredentialOAuthStatus,
	refresher OAuthTokenRefresher,
	now time.Time,
) (*time.Time, bool, *time.Time, error) {
	expiresAt, err := expiresAtFromValues(values)
	if err != nil {
		return nil, false, nil, err
	}
	nextRefreshAfter := scheduledNextRefreshAfter(currentStatus, refresher, expiresAt)
	return expiresAt, nextRefreshAfter == nil || !now.Before(*nextRefreshAfter), nextRefreshAfter, nil
}

func evaluateEnsureFresh(
	currentStatus *platformv1alpha1.CredentialOAuthStatus,
	refresher OAuthTokenRefresher,
	now time.Time,
	minTTL time.Duration,
	expiresAt *time.Time,
) (*time.Time, bool, *time.Time, error) {
	if minTTL < 0 {
		minTTL = 0
	}
	if expiresAt == nil {
		return nil, true, scheduledNextRefreshAfter(currentStatus, refresher, nil), nil
	}
	minTTLBoundary := expiresAt.Add(-minTTL)
	return expiresAt, !now.Before(minTTLBoundary), scheduledNextRefreshAfter(currentStatus, refresher, expiresAt), nil
}

func scheduledNextRefreshAfter(
	_ *platformv1alpha1.CredentialOAuthStatus,
	refresher OAuthTokenRefresher,
	expiresAt *time.Time,
) *time.Time {
	return nextOAuthRefreshAfter(expiresAt, refresher.RefreshLead())
}
