package oauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	modelcatalogdiscoveryv1 "code-code.internal/go-contract/model_catalog_discovery/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	providerv1 "code-code.internal/go-contract/provider/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	"google.golang.org/protobuf/proto"
)

// ResolveOAuthProjection applies CLI-declared artifact projection to one
// OAuth artifact and returns the projected stable account fields.
func ResolveOAuthProjection(cli *supportv1.CLI, artifact *credentialcontract.OAuthArtifact) (*credentialcontract.OAuthArtifact, error) {
	if cli == nil || cli.GetOauth() == nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: cli oauth support is nil")
	}
	if artifact == nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: oauth artifact is nil")
	}
	resolved := cloneOAuthArtifact(artifact)
	projection := cli.GetOauth().GetArtifactProjection()
	if projection == nil {
		return resolved, nil
	}

	for _, mapping := range projection.GetFieldMappings() {
		value, err := projectionValue(mapping.GetSource(), mapping.GetJsonPointer(), artifact)
		if err != nil {
			return nil, err
		}
		switch mapping.GetTarget() {
		case supportv1.OAuthArtifactTargetField_O_AUTH_ARTIFACT_TARGET_FIELD_ACCOUNT_ID:
			if value == "" && mapping.GetFallbackToSubject() {
				value, err = idTokenSubject(artifact)
				if err != nil {
					return nil, err
				}
			}
			if value != "" {
				resolved.AccountID = value
			}
		case supportv1.OAuthArtifactTargetField_O_AUTH_ARTIFACT_TARGET_FIELD_ACCOUNT_EMAIL:
			if value != "" {
				resolved.AccountEmail = value
			}
		}
	}
	return resolved, nil
}

// ResolveOAuthModelCatalog resolves the default CLI OAuth model catalog.
func ResolveOAuthModelCatalog(cli *supportv1.CLI) (*providerv1.ProviderModelCatalog, error) {
	if cli == nil || cli.GetOauth() == nil || cli.GetOauth().GetModelCatalog() == nil {
		return nil, nil
	}
	selected := cli.GetOauth().GetModelCatalog().GetDefaultCatalog()
	if selected == nil {
		return nil, nil
	}
	catalog := proto.Clone(selected).(*providerv1.ProviderModelCatalog)
	normalizeOAuthCatalogModels(catalog)
	if catalog.GetSource() == providerv1.CatalogSource_CATALOG_SOURCE_UNSPECIFIED && len(catalog.GetModels()) > 0 {
		catalog.Source = providerv1.CatalogSource_CATALOG_SOURCE_FALLBACK_CONFIG
	}
	runtime := &providerv1.ProviderSurfaceRuntime{
		DisplayName: oauthCatalogValidationDisplayName(cli),
		Origin:      providerv1.ProviderSurfaceOrigin_PROVIDER_SURFACE_ORIGIN_DERIVED,
		Catalog:     catalog,
		Access: &providerv1.ProviderSurfaceRuntime_Cli{
			Cli: &providerv1.ProviderCLISurfaceRuntime{CliId: strings.TrimSpace(cli.GetCliId())},
		},
	}
	if err := providerv1.ValidateProviderSurfaceRuntime(runtime); err != nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: invalid cli oauth model catalog: %w", err)
	}
	return catalog, nil
}

func ResolveOAuthModelCatalogDiscovery(cli *supportv1.CLI) (*supportv1.OAuthModelCatalogDiscovery, *modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation, error) {
	if cli == nil || cli.GetOauth() == nil || cli.GetOauth().GetModelCatalog() == nil {
		return nil, nil, nil
	}
	configured := cli.GetOauth().GetModelCatalog().GetAuthenticatedDiscovery()
	if configured == nil || configured.GetOperation() == nil {
		return nil, nil, nil
	}
	operation := proto.Clone(configured.GetOperation()).(*modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation)
	if strings.TrimSpace(operation.GetPath()) == "" {
		return nil, nil, fmt.Errorf("platformk8s/clidefinitions: cli oauth model catalog operation path is empty")
	}
	if operation.GetResponseKind() == modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_UNSPECIFIED {
		return nil, nil, fmt.Errorf("platformk8s/clidefinitions: cli oauth model catalog operation response kind is unspecified")
	}
	return proto.Clone(configured).(*supportv1.OAuthModelCatalogDiscovery), operation, nil
}

func normalizeOAuthCatalogModels(catalog *providerv1.ProviderModelCatalog) {
	if catalog == nil {
		return
	}
	for _, model := range catalog.GetModels() {
		if model == nil || strings.TrimSpace(model.GetProviderModelId()) != "" {
			continue
		}
		if fallbackProviderModelID := strings.TrimSpace(model.GetModelRef().GetModelId()); fallbackProviderModelID != "" {
			model.ProviderModelId = fallbackProviderModelID
		}
	}
}

func oauthCatalogValidationDisplayName(pkg *supportv1.CLI) string {
	if name := strings.TrimSpace(pkg.GetDisplayName()); name != "" {
		return name
	}
	if cliID := strings.TrimSpace(pkg.GetCliId()); cliID != "" {
		return cliID
	}
	return "oauth-catalog-validation"
}

func projectionValue(source supportv1.OAuthArtifactSource, pointer string, artifact *credentialcontract.OAuthArtifact) (string, error) {
	document, err := projectionDocument(source, artifact)
	if err != nil {
		return "", err
	}
	return stringAtJSONPointer(document, pointer)
}

func projectionDocument(source supportv1.OAuthArtifactSource, artifact *credentialcontract.OAuthArtifact) (any, error) {
	switch source {
	case supportv1.OAuthArtifactSource_O_AUTH_ARTIFACT_SOURCE_TOKEN_RESPONSE:
		if strings.TrimSpace(artifact.TokenResponseJSON) == "" {
			return nil, fmt.Errorf("platformk8s/clidefinitions: oauth token response json is empty")
		}
		var value any
		if err := json.Unmarshal([]byte(artifact.TokenResponseJSON), &value); err != nil {
			return nil, fmt.Errorf("platformk8s/clidefinitions: decode oauth token response json: %w", err)
		}
		return value, nil
	case supportv1.OAuthArtifactSource_O_AUTH_ARTIFACT_SOURCE_ID_TOKEN_CLAIMS:
		if strings.TrimSpace(artifact.IDToken) == "" {
			return nil, fmt.Errorf("platformk8s/clidefinitions: oauth id token is empty")
		}
		return idTokenClaimsDocument(artifact.IDToken)
	default:
		return nil, fmt.Errorf("platformk8s/clidefinitions: oauth artifact source is unspecified")
	}
}

func idTokenSubject(artifact *credentialcontract.OAuthArtifact) (string, error) {
	document, err := projectionDocument(supportv1.OAuthArtifactSource_O_AUTH_ARTIFACT_SOURCE_ID_TOKEN_CLAIMS, artifact)
	if err != nil {
		return "", err
	}
	return stringAtJSONPointer(document, "/sub")
}

func idTokenClaimsDocument(idToken string) (any, error) {
	parts := strings.Split(strings.TrimSpace(idToken), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("platformk8s/clidefinitions: oauth id token format is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: decode oauth id token payload: %w", err)
	}
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: decode oauth id token claims: %w", err)
	}
	return value, nil
}

func stringAtJSONPointer(document any, pointer string) (string, error) {
	current := document
	if strings.TrimSpace(pointer) == "" || pointer == "/" {
		return "", fmt.Errorf("platformk8s/clidefinitions: oauth json pointer is empty")
	}
	for _, token := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		key := strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		next, ok := current.(map[string]any)
		if !ok {
			return "", nil
		}
		current, ok = next[key]
		if !ok {
			return "", nil
		}
	}
	switch value := current.(type) {
	case string:
		return strings.TrimSpace(value), nil
	default:
		return "", nil
	}
}

func cloneOAuthArtifact(artifact *credentialcontract.OAuthArtifact) *credentialcontract.OAuthArtifact {
	if artifact == nil {
		return nil
	}
	next := *artifact
	next.Scopes = append([]string(nil), artifact.Scopes...)
	return &next
}
