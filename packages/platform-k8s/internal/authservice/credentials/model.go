package credentials

import (
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	"code-code.internal/go-contract/domainerror"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"code-code.internal/platform-k8s/internal/platform/resourcemeta"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Credential struct {
	definition *credentialv1.CredentialDefinition
	material   *credentialv1.ResolvedCredential
}

func NewCredential(
	definition *credentialv1.CredentialDefinition,
	material *credentialv1.ResolvedCredential,
) (*Credential, error) {
	if definition == nil {
		return nil, domainerror.NewValidation("platformk8s/credentials: credential definition is nil")
	}
	displayName := strings.TrimSpace(definition.GetDisplayName())
	if displayName == "" {
		return nil, domainerror.NewValidation("platformk8s/credentials: credential display name is required")
	}
	credentialID, err := resourcemeta.EnsureResourceID(definition.GetCredentialId(), displayName, "credential")
	if err != nil {
		return nil, err
	}
	nextDefinition := cloneCredentialDefinition(definition)
	nextDefinition.CredentialId = credentialID
	nextDefinition.DisplayName = displayName
	nextDefinition.VendorId = strings.TrimSpace(nextDefinition.GetVendorId())
	if oauth := nextDefinition.GetOauthMetadata(); oauth != nil {
		oauth.CliId = strings.TrimSpace(oauth.GetCliId())
	}
	if session := nextDefinition.GetSessionMetadata(); session != nil {
		session.SchemaId = strings.TrimSpace(session.GetSchemaId())
		session.RequiredKeys = trimNonEmpty(session.GetRequiredKeys())
	}
	nextMaterial := cloneResolvedCredential(material)
	if nextMaterial != nil {
		if nextMaterial.GetCredentialId() == "" {
			nextMaterial.CredentialId = credentialID
		}
		if strings.TrimSpace(nextMaterial.GetCredentialId()) != credentialID {
			return nil, domainerror.NewValidation(
				"platformk8s/credentials: credential id %q does not match material %q",
				credentialID,
				nextMaterial.GetCredentialId(),
			)
		}
		if nextMaterial.GetKind() == credentialv1.CredentialKind_CREDENTIAL_KIND_UNSPECIFIED {
			nextMaterial.Kind = nextDefinition.GetKind()
		}
		if nextMaterial.GetKind() != nextDefinition.GetKind() {
			return nil, domainerror.NewValidation(
				"platformk8s/credentials: credential kind %q does not match material %q",
				nextDefinition.GetKind().String(),
				nextMaterial.GetKind().String(),
			)
		}
		normalizeCredentialMaterial(nextMaterial)
	}
	if err := credentialv1.ValidateDefinition(nextDefinition); err != nil {
		return nil, domainerror.NewValidation("platformk8s/credentials: invalid credential definition: %v", err)
	}
	if err := validateCredentialMaterial(nextDefinition, nextMaterial); err != nil {
		return nil, err
	}
	return &Credential{
		definition: nextDefinition,
		material:   nextMaterial,
	}, nil
}

func (c *Credential) ID() string {
	if c == nil || c.definition == nil {
		return ""
	}
	return strings.TrimSpace(c.definition.GetCredentialId())
}

func (c *Credential) Definition() *credentialv1.CredentialDefinition {
	if c == nil || c.definition == nil {
		return nil
	}
	return proto.Clone(c.definition).(*credentialv1.CredentialDefinition)
}

func (c *Credential) Material() *credentialv1.ResolvedCredential {
	if c == nil || c.material == nil {
		return nil
	}
	return proto.Clone(c.material).(*credentialv1.ResolvedCredential)
}

func (c *Credential) WithID(credentialID string) *Credential {
	if c == nil || c.definition == nil {
		return nil
	}
	nextDefinition := c.Definition()
	nextDefinition.CredentialId = strings.TrimSpace(credentialID)
	nextMaterial := c.Material()
	if nextMaterial != nil {
		nextMaterial.CredentialId = strings.TrimSpace(credentialID)
	}
	return &Credential{
		definition: nextDefinition,
		material:   nextMaterial,
	}
}

func (c *Credential) Resource(namespace string) *platformv1alpha1.CredentialDefinitionResource {
	return &platformv1alpha1.CredentialDefinitionResource{
		TypeMeta: metav1.TypeMeta{
			APIVersion: platformv1alpha1.GroupVersion.String(),
			Kind:       platformv1alpha1.KindCredentialDefinitionResource,
		},
		ObjectMeta: metav1.ObjectMeta{Name: c.ID(), Namespace: namespace},
		Spec: platformv1alpha1.CredentialDefinitionResourceSpec{
			Definition: c.Definition(),
		},
	}
}

func cloneCredentialDefinition(definition *credentialv1.CredentialDefinition) *credentialv1.CredentialDefinition {
	if definition == nil {
		return nil
	}
	return proto.Clone(definition).(*credentialv1.CredentialDefinition)
}

func cloneResolvedCredential(material *credentialv1.ResolvedCredential) *credentialv1.ResolvedCredential {
	if material == nil {
		return nil
	}
	return proto.Clone(material).(*credentialv1.ResolvedCredential)
}

func normalizeCredentialMaterial(material *credentialv1.ResolvedCredential) {
	if material == nil {
		return
	}
	material.CredentialId = strings.TrimSpace(material.GetCredentialId())
	if apiKey := material.GetApiKey(); apiKey != nil {
		apiKey.ApiKey = strings.TrimSpace(apiKey.GetApiKey())
	}
	if oauth := material.GetOauth(); oauth != nil {
		oauth.AccessToken = strings.TrimSpace(oauth.GetAccessToken())
		oauth.TokenType = strings.TrimSpace(oauth.GetTokenType())
		oauth.AccountId = strings.TrimSpace(oauth.GetAccountId())
		oauth.Scopes = trimNonEmpty(oauth.GetScopes())
		oauth.RefreshToken = strings.TrimSpace(oauth.GetRefreshToken())
		oauth.IdToken = strings.TrimSpace(oauth.GetIdToken())
	}
	if session := material.GetSession(); session != nil {
		session.SchemaId = strings.TrimSpace(session.GetSchemaId())
		session.Values = trimSessionValues(session.GetValues())
	}
}

func validateCredentialMaterial(definition *credentialv1.CredentialDefinition, material *credentialv1.ResolvedCredential) error {
	if definition == nil || material == nil {
		return nil
	}
	switch definition.GetKind() {
	case credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY:
		if strings.TrimSpace(material.GetApiKey().GetApiKey()) == "" {
			return domainerror.NewValidation("platformk8s/credentials: api key is required")
		}
	case credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH:
		if strings.TrimSpace(material.GetOauth().GetAccessToken()) == "" {
			return domainerror.NewValidation("platformk8s/credentials: access token is required")
		}
	case credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION:
		session := material.GetSession()
		if session == nil {
			return domainerror.NewValidation("platformk8s/credentials: session material is required")
		}
		schemaID := strings.TrimSpace(session.GetSchemaId())
		if schemaID == "" {
			return domainerror.NewValidation("platformk8s/credentials: session schema_id is required")
		}
		if metadata := definition.GetSessionMetadata(); metadata != nil {
			if expected := strings.TrimSpace(metadata.GetSchemaId()); expected != "" && expected != schemaID {
				return domainerror.NewValidation(
					"platformk8s/credentials: session schema_id %q does not match definition %q",
					schemaID,
					expected,
				)
			}
			for _, key := range metadata.GetRequiredKeys() {
				if value := strings.TrimSpace(session.GetValues()[key]); value == "" {
					return domainerror.NewValidation("platformk8s/credentials: session key %q is required", key)
				}
			}
		}
	}
	return nil
}

func trimSessionValues(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	trimmed := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		trimmed[key] = value
	}
	if len(trimmed) == 0 {
		return nil
	}
	return trimmed
}
