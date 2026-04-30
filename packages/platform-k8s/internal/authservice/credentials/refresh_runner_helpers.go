package credentials

import (
	"fmt"
	"strings"
	"time"

	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
