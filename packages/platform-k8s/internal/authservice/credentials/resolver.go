package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	credentialcontract "code-code.internal/agent-runtime-contract/credential"
	credentialv1 "code-code.internal/go-contract/credential/v1"
	"code-code.internal/go-contract/domainerror"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"google.golang.org/protobuf/proto"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	materialKeyAPIKey      = "api_key"
	materialKeyAccessToken = "access_token"
	materialKeyTokenType   = "token_type"
	materialKeyExpiresAt   = "expires_at"
	materialKeyAccountID   = "account_id"
	materialKeyScopes      = "scopes"
)

// Resolver resolves credentials from the auth-owned definition and material stores.
type Resolver struct {
	client        ctrlclient.Client
	namespace     string
	store         ResourceStore
	materialStore CredentialMaterialStore
}

// NewResolver creates one credential resolver.
func NewResolver(k8sClient ctrlclient.Client, namespace string, materialStore CredentialMaterialStore) (*Resolver, error) {
	if k8sClient == nil {
		return nil, fmt.Errorf("platformk8s/credentials: client is nil")
	}
	if namespace == "" {
		return nil, fmt.Errorf("platformk8s/credentials: namespace is empty")
	}
	store, err := NewKubernetesResourceStore(k8sClient, namespace)
	if err != nil {
		return nil, err
	}
	return NewResolverWithStores(k8sClient, namespace, store, materialStore)
}

func NewResolverWithStores(
	k8sClient ctrlclient.Client,
	namespace string,
	store ResourceStore,
	materialStore CredentialMaterialStore,
) (*Resolver, error) {
	if k8sClient == nil {
		return nil, fmt.Errorf("platformk8s/credentials: client is nil")
	}
	if namespace == "" {
		return nil, fmt.Errorf("platformk8s/credentials: namespace is empty")
	}
	if store == nil {
		return nil, fmt.Errorf("platformk8s/credentials: resource store is nil")
	}
	if materialStore == nil {
		return nil, fmt.Errorf("platformk8s/credentials: material store is nil")
	}
	return &Resolver{client: k8sClient, namespace: namespace, store: store, materialStore: materialStore}, nil
}

// Get returns the configured credential definition referenced by ref.
func (r *Resolver) Get(ctx context.Context, ref *credentialcontract.CredentialRef) (*credentialcontract.CredentialDefinition, error) {
	resource, err := r.getResource(ctx, ref)
	if err != nil {
		return nil, err
	}
	return materializeDefinition(resource)
}

// Resolve returns the provider-ready credential material referenced by ref.
func (r *Resolver) Resolve(ctx context.Context, ref *credentialcontract.CredentialRef) (*credentialcontract.ResolvedCredential, error) {
	resource, err := r.getResource(ctx, ref)
	if err != nil {
		return nil, err
	}
	definition, err := materializeDefinition(resource)
	if err != nil {
		return nil, err
	}
	values, err := r.materialStore.ReadValues(ctx, definition.GetCredentialId())
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, domainerror.NewNotFound("platformk8s/credentials: material not found for credential %q", definition.CredentialId)
		}
		return nil, fmt.Errorf("platformk8s/credentials: read credential material %q: %w", definition.CredentialId, err)
	}

	resolved, err := resolveFromValues(definition, values, materializeOAuthStatus(resource))
	if err != nil {
		return nil, err
	}
	if err := credentialv1.ValidateResolvedCredential(resolved); err != nil {
		return nil, domainerror.NewValidation("platformk8s/credentials: invalid resolved credential %q: %v", definition.CredentialId, err)
	}
	return resolved, nil
}

func (r *Resolver) getResource(ctx context.Context, ref *credentialcontract.CredentialRef) (*platformv1alpha1.CredentialDefinitionResource, error) {
	if err := credentialv1.ValidateRef(ref); err != nil {
		return nil, err
	}
	resource, err := r.store.Get(ctx, ref.CredentialId)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, domainerror.NewNotFound("platformk8s/credentials: credential %q not found", ref.CredentialId)
		}
		return nil, fmt.Errorf("platformk8s/credentials: get credential %q: %w", ref.CredentialId, err)
	}
	return resource, nil
}

func materializeDefinition(resource *platformv1alpha1.CredentialDefinitionResource) (*credentialv1.CredentialDefinition, error) {
	if resource == nil {
		return nil, domainerror.NewValidation("platformk8s/credentials: credential resource is nil")
	}
	definition := &credentialv1.CredentialDefinition{}
	if resource.Spec.Definition != nil {
		definition = proto.Clone(resource.Spec.Definition).(*credentialv1.CredentialDefinition)
	}
	if definition.CredentialId == "" {
		definition.CredentialId = resource.GetName()
	} else if definition.CredentialId != resource.GetName() {
		return nil, domainerror.NewValidation("platformk8s/credentials: credential id %q does not match resource name %q", definition.CredentialId, resource.GetName())
	}
	if err := credentialv1.ValidateDefinition(definition); err != nil {
		return nil, domainerror.NewValidation("platformk8s/credentials: invalid credential %q: %v", resource.GetName(), err)
	}
	return definition, nil
}

func resolveFromValues(definition *credentialv1.CredentialDefinition, values map[string]string, oauthStatus *platformv1alpha1.CredentialOAuthStatus) (*credentialv1.ResolvedCredential, error) {
	_ = oauthStatus
	switch definition.Kind {
	case credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY:
		value, err := getRequiredValue(values, materialKeyAPIKey)
		if err != nil {
			return nil, domainerror.NewValidation("platformk8s/credentials: resolve api key credential %q: %v", definition.CredentialId, err)
		}
		return &credentialv1.ResolvedCredential{
			CredentialId: definition.CredentialId,
			Kind:         definition.Kind,
			Material: &credentialv1.ResolvedCredential_ApiKey{
				ApiKey: &credentialv1.ApiKeyCredential{
					ApiKey: value,
				},
			},
		}, nil
	case credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH:
		accessToken, err := getRequiredValue(values, materialKeyAccessToken)
		if err != nil {
			return nil, domainerror.NewValidation("platformk8s/credentials: resolve oauth credential %q: %v", definition.CredentialId, err)
		}
		oauth := &credentialv1.OAuthCredential{
			AccessToken:  accessToken,
			TokenType:    getOptionalValue(values, materialKeyTokenType),
			AccountId:    getOptionalValue(values, materialKeyAccountID),
			Scopes:       parseScopes(getOptionalValue(values, materialKeyScopes)),
			RefreshToken: getOptionalValue(values, materialKeyRefreshToken),
			IdToken:      getOptionalValue(values, materialKeyIDToken),
		}
		expiresAtRaw := getOptionalValue(values, materialKeyExpiresAt)
		if expiresAtRaw != "" {
			expiresAt, err := time.Parse(time.RFC3339, expiresAtRaw)
			if err != nil {
				return nil, domainerror.NewValidation("platformk8s/credentials: parse oauth expires_at for credential %q: %v", definition.CredentialId, err)
			}
			oauth.ExpiresAt = timestamppb.New(expiresAt)
		}
		return &credentialv1.ResolvedCredential{
			CredentialId: definition.CredentialId,
			Kind:         definition.Kind,
			Material: &credentialv1.ResolvedCredential_Oauth{
				Oauth: oauth,
			},
		}, nil
	case credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION:
		sessionMetadata := definition.GetSessionMetadata()
		for _, key := range sessionMetadata.GetRequiredKeys() {
			if strings.TrimSpace(values[key]) == "" {
				return nil, domainerror.NewValidation(
					"platformk8s/credentials: resolve session credential %q: material key %q is empty",
					definition.CredentialId,
					key,
				)
			}
		}
		return &credentialv1.ResolvedCredential{
			CredentialId: definition.CredentialId,
			Kind:         definition.Kind,
			Material: &credentialv1.ResolvedCredential_Session{
				Session: &credentialv1.SessionCredential{
					SchemaId: strings.TrimSpace(sessionMetadata.GetSchemaId()),
					Values:   values,
				},
			},
		}, nil
	default:
		return nil, domainerror.NewValidation("platformk8s/credentials: unsupported credential kind %s", definition.Kind.String())
	}
}

func materializeOAuthStatus(resource *platformv1alpha1.CredentialDefinitionResource) *platformv1alpha1.CredentialOAuthStatus {
	if resource == nil || resource.Status.OAuth == nil {
		return nil
	}
	return resource.Status.OAuth.DeepCopy()
}

func getRequiredValue(values map[string]string, key string) (string, error) {
	value := getOptionalValue(values, key)
	if value == "" {
		return "", domainerror.NewValidation("material key %q is empty", key)
	}
	return value, nil
}

func getOptionalValue(values map[string]string, key string) string {
	if key == "" {
		return ""
	}
	return strings.TrimSpace(values[key])
}

func parseScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "[") {
		var scopes []string
		if err := json.Unmarshal([]byte(raw), &scopes); err == nil {
			return trimNonEmpty(scopes)
		}
	}
	return trimNonEmpty(strings.Split(raw, ","))
}

func trimNonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}
