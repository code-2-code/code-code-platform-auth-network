package credentials

import (
	"context"
	"fmt"
	"strings"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	clioauth "code-code.internal/platform-k8s/internal/supportservice/clidefinitions/oauth"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (r *RefreshRunner) refreshedOAuthArtifact(
	ctx context.Context,
	cliID string,
	values map[string]string,
	result *OAuthRefreshResult,
	definition *credentialv1.CredentialDefinition,
	currentStatus *platformv1alpha1.CredentialOAuthStatus,
	now time.Time,
	refreshLead time.Duration,
) (*credentialcontract.OAuthArtifact, *platformv1alpha1.CredentialOAuthStatus, error) {
	artifact := mergeRefreshResultWithValues(values, result)
	status := r.oauthStatusFromDefinition(definition, currentStatus)
	status.CredentialGeneration++
	status.LastRefreshedAt = &metav1.Time{Time: now}
	nextRefreshAfter := nextOAuthRefreshAfter(
		artifact.ExpiresAt,
		refreshLead,
	)
	if nextRefreshAfter != nil {
		status.NextRefreshAfter = &metav1.Time{Time: *nextRefreshAfter}
	} else {
		status.NextRefreshAfter = nil
	}

	if r == nil || r.cliSupport == nil {
		if artifact.AccountEmail != "" {
			status.AccountEmail = artifact.AccountEmail
		}
		return artifact, status, fmt.Errorf("credentials: cli support service is not initialized")
	}
	cli, err := r.cliSupport.Get(ctx, strings.TrimSpace(cliID))
	if err != nil {
		if artifact.AccountEmail != "" {
			status.AccountEmail = artifact.AccountEmail
		}
		return artifact, status, fmt.Errorf("credentials: resolve cli support %q: %w", cliID, err)
	}
	projectedArtifact, err := clioauth.ResolveOAuthProjection(cli, artifact)
	if err != nil {
		if artifact.AccountEmail != "" {
			status.AccountEmail = artifact.AccountEmail
		}
		return artifact, status, fmt.Errorf("credentials: resolve cli oauth projection for %q: %w", cliID, err)
	}
	if projectedArtifact.AccountEmail != "" {
		status.AccountEmail = projectedArtifact.AccountEmail
	}
	return projectedArtifact, status, nil
}

func mergeRefreshResultWithValues(values map[string]string, result *OAuthRefreshResult) *credentialcontract.OAuthArtifact {
	artifact := &credentialcontract.OAuthArtifact{
		AccessToken:       strings.TrimSpace(result.AccessToken),
		RefreshToken:      valueOr(result.RefreshToken, values, materialKeyRefreshToken),
		IDToken:           valueOr(result.IDToken, values, materialKeyIDToken),
		TokenResponseJSON: valueOr(result.TokenResponseJSON, values, materialKeyTokenResponse),
		TokenType:         valueOr(result.TokenType, values, materialKeyTokenType),
		AccountID:         valueOr(result.AccountID, values, materialKeyAccountID),
		AccountEmail:      valueOr(result.AccountEmail, values, materialKeyAccountEmail),
		Scopes:            scopesOr(result.Scopes, values),
		ExpiresAt:         expiresAtOr(result.ExpiresAt, values),
	}
	return artifact
}

func valueOr(next string, values map[string]string, key string) string {
	trimmed := strings.TrimSpace(next)
	if trimmed != "" {
		return trimmed
	}
	return strings.TrimSpace(values[key])
}

func scopesOr(next []string, values map[string]string) []string {
	if len(next) > 0 {
		return append([]string(nil), next...)
	}
	return parseScopes(strings.TrimSpace(values[materialKeyScopes]))
}

func expiresAtOr(next *time.Time, values map[string]string) *time.Time {
	if next != nil && !next.IsZero() {
		value := next.UTC()
		return &value
	}
	raw := strings.TrimSpace(values[materialKeyExpiresAt])
	if raw == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil
	}
	value := parsed.UTC()
	return &value
}
