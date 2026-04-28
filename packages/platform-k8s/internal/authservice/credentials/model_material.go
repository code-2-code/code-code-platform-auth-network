package credentials

import (
	"strings"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	"code-code.internal/go-contract/domainerror"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (c *Credential) MaterialValues() (map[string]string, error) {
	if c == nil || c.definition == nil {
		return nil, domainerror.NewValidation("platformk8s/credentials: credential is nil")
	}
	if err := validateCredentialMaterial(c.definition, c.material); err != nil {
		return nil, err
	}
	if c.material == nil {
		return nil, domainerror.NewValidation("platformk8s/credentials: credential material is required")
	}
	values := map[string]string{}
	switch c.definition.GetKind() {
	case credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY:
		values[materialKeyAPIKey] = c.material.GetApiKey().GetApiKey()
	case credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH:
		oauth := c.material.GetOauth()
		values[materialKeyAccessToken] = oauth.GetAccessToken()
		if oauth.GetTokenType() != "" {
			values[materialKeyTokenType] = oauth.GetTokenType()
		}
		if oauth.GetAccountId() != "" {
			values[materialKeyAccountID] = oauth.GetAccountId()
		}
		if len(oauth.GetScopes()) > 0 {
			values[materialKeyScopes] = strings.Join(trimNonEmpty(oauth.GetScopes()), ",")
		}
		if expiresAt := oauth.GetExpiresAt(); expiresAt != nil {
			values[materialKeyExpiresAt] = expiresAt.AsTime().UTC().Format(time.RFC3339)
		}
		if oauth.GetRefreshToken() != "" {
			values[materialKeyRefreshToken] = oauth.GetRefreshToken()
		}
		if oauth.GetIdToken() != "" {
			values[materialKeyIDToken] = oauth.GetIdToken()
		}
	case credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION:
		for key, value := range c.material.GetSession().GetValues() {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key == "" || value == "" {
				continue
			}
			values[key] = value
		}
	default:
		return nil, domainerror.NewValidation("platformk8s/credentials: unsupported credential kind %q", c.definition.GetKind().String())
	}
	return trimMaterialValueUpdates(values), nil
}

func (c *Credential) PreserveMissingMaterialValues(values map[string]string) {
	if c == nil || c.definition == nil {
		return
	}
	switch c.definition.GetKind() {
	case credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY:
		if c.material == nil {
			c.material = &credentialv1.ResolvedCredential{CredentialId: c.ID(), Kind: c.definition.GetKind()}
		}
		if c.material.Material == nil || c.material.GetApiKey().GetApiKey() == "" {
			c.material.Material = &credentialv1.ResolvedCredential_ApiKey{
				ApiKey: &credentialv1.ApiKeyCredential{
					ApiKey: strings.TrimSpace(values[materialKeyAPIKey]),
				},
			}
		}
	case credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH:
		if c.material == nil {
			c.material = &credentialv1.ResolvedCredential{
				CredentialId: c.ID(),
				Kind:         c.definition.GetKind(),
				Material:     &credentialv1.ResolvedCredential_Oauth{Oauth: &credentialv1.OAuthCredential{}},
			}
		}
		if c.material.GetOauth() == nil {
			c.material.Material = &credentialv1.ResolvedCredential_Oauth{Oauth: &credentialv1.OAuthCredential{}}
		}
		oauth := c.material.GetOauth()
		if oauth.GetAccessToken() == "" {
			oauth.AccessToken = strings.TrimSpace(values[materialKeyAccessToken])
		}
		if oauth.GetTokenType() == "" {
			oauth.TokenType = strings.TrimSpace(values[materialKeyTokenType])
		}
		if oauth.GetAccountId() == "" {
			oauth.AccountId = strings.TrimSpace(values[materialKeyAccountID])
		}
		if len(oauth.GetScopes()) == 0 {
			oauth.Scopes = trimNonEmpty(strings.Split(strings.TrimSpace(values[materialKeyScopes]), ","))
		}
		if oauth.GetExpiresAt() == nil {
			if raw := strings.TrimSpace(values[materialKeyExpiresAt]); raw != "" {
				if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
					oauth.ExpiresAt = timestamppb.New(parsed)
				}
			}
		}
		if oauth.GetRefreshToken() == "" {
			oauth.RefreshToken = strings.TrimSpace(values[materialKeyRefreshToken])
		}
		if oauth.GetIdToken() == "" {
			oauth.IdToken = strings.TrimSpace(values[materialKeyIDToken])
		}
	case credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION:
		if c.material == nil {
			c.material = &credentialv1.ResolvedCredential{
				CredentialId: c.ID(),
				Kind:         c.definition.GetKind(),
				Material: &credentialv1.ResolvedCredential_Session{
					Session: &credentialv1.SessionCredential{},
				},
			}
		}
		if c.material.GetSession() == nil {
			c.material.Material = &credentialv1.ResolvedCredential_Session{Session: &credentialv1.SessionCredential{}}
		}
		session := c.material.GetSession()
		if session.GetSchemaId() == "" {
			if metadata := c.definition.GetSessionMetadata(); metadata != nil {
				session.SchemaId = strings.TrimSpace(metadata.GetSchemaId())
			}
		}
		if len(session.GetValues()) == 0 {
			session.Values = trimSessionValues(values)
		}
	}
}
