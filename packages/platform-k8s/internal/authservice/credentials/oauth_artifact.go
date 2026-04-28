package credentials

import (
	"fmt"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
)

func OAuthArtifactFromValues(values map[string]string) (*credentialcontract.OAuthArtifact, error) {
	artifact := &credentialcontract.OAuthArtifact{
		AccessToken:       getOptionalValue(values, materialKeyAccessToken),
		RefreshToken:      getOptionalValue(values, materialKeyRefreshToken),
		IDToken:           getOptionalValue(values, materialKeyIDToken),
		TokenResponseJSON: getOptionalValue(values, materialKeyTokenResponse),
		TokenType:         getOptionalValue(values, materialKeyTokenType),
		AccountID:         getOptionalValue(values, materialKeyAccountID),
		AccountEmail:      getOptionalValue(values, materialKeyAccountEmail),
		Scopes:            parseScopes(getOptionalValue(values, materialKeyScopes)),
	}
	if raw := getOptionalValue(values, materialKeyExpiresAt); raw != "" {
		expiresAt, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return nil, fmt.Errorf("platformk8s/credentials: parse oauth expires_at: %w", err)
		}
		artifact.ExpiresAt = &expiresAt
	}
	if err := credentialcontract.ValidateOAuthArtifact(artifact); err != nil {
		return nil, fmt.Errorf("platformk8s/credentials: invalid oauth artifact material: %w", err)
	}
	return artifact, nil
}
