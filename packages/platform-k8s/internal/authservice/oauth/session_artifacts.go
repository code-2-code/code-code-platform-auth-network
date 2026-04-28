package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
	corev1 "k8s.io/api/core/v1"
)

func (s *OAuthSessionSecretStore) PutArtifact(ctx context.Context, cliID, sessionID string, artifact *credentialcontract.OAuthArtifact) error {
	if err := credentialcontract.ValidateOAuthArtifact(artifact); err != nil {
		return err
	}
	return s.updateSessionSecret(ctx, cliID, sessionID, func(data map[string][]byte) error {
		data[oauthAccessTokenKey] = []byte(strings.TrimSpace(artifact.AccessToken))
		data[oauthRefreshTokenKey] = []byte(strings.TrimSpace(artifact.RefreshToken))
		data[oauthIDTokenKey] = []byte(strings.TrimSpace(artifact.IDToken))
		data[oauthTokenResponseJSONKey] = []byte(strings.TrimSpace(artifact.TokenResponseJSON))
		data[oauthTokenTypeKey] = []byte(strings.TrimSpace(artifact.TokenType))
		data[oauthAccountIDKey] = []byte(strings.TrimSpace(artifact.AccountID))
		data[oauthAccountEmailKey] = []byte(strings.TrimSpace(artifact.AccountEmail))
		data[oauthScopesKey] = []byte(strings.Join(artifact.Scopes, " "))
		if artifact.ExpiresAt != nil && !artifact.ExpiresAt.IsZero() {
			data[oauthSessionExpiresAtKey] = []byte(artifact.ExpiresAt.UTC().Format(time.RFC3339))
		}
		return nil
	})
}

func (s *OAuthSessionSecretStore) GetArtifact(ctx context.Context, cliID, sessionID string) (*credentialcontract.OAuthArtifact, error) {
	secret, err := s.getSessionSecret(ctx, cliID, sessionID)
	if err != nil {
		return nil, err
	}
	return artifactFromSecret(secret)
}

func (s *OAuthSessionSecretStore) GetArtifactIfPresent(ctx context.Context, cliID, sessionID string) (*credentialcontract.OAuthArtifact, error) {
	secret, err := s.getSessionSecret(ctx, cliID, sessionID)
	if err != nil {
		return nil, err
	}
	return artifactFromSecretIfPresent(secret)
}

func artifactFromSecret(secret *corev1.Secret) (*credentialcontract.OAuthArtifact, error) {
	if secret == nil {
		return nil, fmt.Errorf("platformk8s: oauth artifact secret is nil")
	}
	artifact := &credentialcontract.OAuthArtifact{
		AccessToken:       strings.TrimSpace(string(secret.Data[oauthAccessTokenKey])),
		RefreshToken:      strings.TrimSpace(string(secret.Data[oauthRefreshTokenKey])),
		IDToken:           strings.TrimSpace(string(secret.Data[oauthIDTokenKey])),
		TokenResponseJSON: strings.TrimSpace(string(secret.Data[oauthTokenResponseJSONKey])),
		TokenType:         strings.TrimSpace(string(secret.Data[oauthTokenTypeKey])),
		AccountID:         strings.TrimSpace(string(secret.Data[oauthAccountIDKey])),
		AccountEmail:      strings.TrimSpace(string(secret.Data[oauthAccountEmailKey])),
		Scopes:            trimNonEmptyStrings(strings.Fields(strings.TrimSpace(string(secret.Data[oauthScopesKey])))),
	}
	if expiresAt, ok := sessionSecretExpiresAt(secret); ok {
		expiresAtCopy := expiresAt
		artifact.ExpiresAt = &expiresAtCopy
	}
	if err := credentialcontract.ValidateOAuthArtifact(artifact); err != nil {
		return nil, err
	}
	return artifact, nil
}

func artifactFromSecretIfPresent(secret *corev1.Secret) (*credentialcontract.OAuthArtifact, error) {
	if secret == nil {
		return nil, fmt.Errorf("platformk8s: oauth artifact secret is nil")
	}
	if strings.TrimSpace(string(secret.Data[oauthAccessTokenKey])) == "" {
		return nil, nil
	}
	return artifactFromSecret(secret)
}
