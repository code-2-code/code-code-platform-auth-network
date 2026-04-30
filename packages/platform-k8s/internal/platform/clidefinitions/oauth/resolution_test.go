package oauth

import (
	"encoding/base64"
	"testing"

	modelv1 "code-code.internal/go-contract/model/v1"
	modelcatalogdiscoveryv1 "code-code.internal/go-contract/model_catalog_discovery/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	providerv1 "code-code.internal/go-contract/provider/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
)

func TestResolveOAuthProjectionProjectsArtifactFields(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "codex",
		Oauth: &supportv1.OAuthSupport{
			ArtifactProjection: &supportv1.OAuthArtifactProjection{
				FieldMappings: []*supportv1.OAuthArtifactFieldMapping{
					{
						Target:      supportv1.OAuthArtifactTargetField_O_AUTH_ARTIFACT_TARGET_FIELD_ACCOUNT_EMAIL,
						Source:      supportv1.OAuthArtifactSource_O_AUTH_ARTIFACT_SOURCE_ID_TOKEN_CLAIMS,
						JsonPointer: "/email",
					},
					{
						Target:            supportv1.OAuthArtifactTargetField_O_AUTH_ARTIFACT_TARGET_FIELD_ACCOUNT_ID,
						Source:            supportv1.OAuthArtifactSource_O_AUTH_ARTIFACT_SOURCE_ID_TOKEN_CLAIMS,
						JsonPointer:       "/https:~1~1api.openai.com~1auth/chatgpt_account_id",
						FallbackToSubject: true,
					},
				},
			},
		},
	}

	artifact, err := ResolveOAuthProjection(pkg, &credentialcontract.OAuthArtifact{
		AccessToken: "access-token",
		IDToken:     testJWT(`{"sub":"acct-sub","email":"dev@example.com","https://api.openai.com/auth":{"chatgpt_account_id":"acct-1"}}`),
	})
	if err != nil {
		t.Fatalf("ResolveOAuthProjection() error = %v", err)
	}
	if got, want := artifact.AccountEmail, "dev@example.com"; got != want {
		t.Fatalf("account_email = %q, want %q", got, want)
	}
	if got, want := artifact.AccountID, "acct-1"; got != want {
		t.Fatalf("account_id = %q, want %q", got, want)
	}
}

func TestResolveOAuthModelCatalogUsesDefaultCatalog(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "codex",
		Oauth: &supportv1.OAuthSupport{
			ModelCatalog: &supportv1.OAuthModelCatalog{
				DefaultCatalog: &providerv1.ProviderModelCatalog{
					Models: []*providerv1.ProviderModelCatalogEntry{{
						ProviderModelId: "gpt-4.1-mini",
					}},
				},
			},
		},
	}

	catalog, err := ResolveOAuthModelCatalog(pkg)
	if err != nil {
		t.Fatalf("ResolveOAuthModelCatalog() error = %v", err)
	}
	if got, want := len(catalog.GetModels()), 1; got != want {
		t.Fatalf("models len = %d, want %d", got, want)
	}
	if got, want := catalog.GetModels()[0].GetProviderModelId(), "gpt-4.1-mini"; got != want {
		t.Fatalf("provider_model_id = %q, want %q", got, want)
	}
	if got, want := catalog.GetSource(), providerv1.CatalogSource_CATALOG_SOURCE_FALLBACK_CONFIG; got != want {
		t.Fatalf("catalog source = %v, want %v", got, want)
	}
}

func TestResolveOAuthModelCatalogBackfillsProviderModelIDFromModelRef(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "gemini-cli",
		Oauth: &supportv1.OAuthSupport{
			ModelCatalog: &supportv1.OAuthModelCatalog{
				DefaultCatalog: &providerv1.ProviderModelCatalog{
					Models: []*providerv1.ProviderModelCatalogEntry{{
						ModelRef: &modelv1.ModelRef{ModelId: "gemini-2.5-pro"},
					}},
				},
			},
		},
	}

	catalog, err := ResolveOAuthModelCatalog(pkg)
	if err != nil {
		t.Fatalf("ResolveOAuthModelCatalog() error = %v", err)
	}
	if got, want := catalog.GetModels()[0].GetProviderModelId(), "gemini-2.5-pro"; got != want {
		t.Fatalf("provider_model_id = %q, want %q", got, want)
	}
}

func TestResolveOAuthModelCatalogDiscovery(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "codex",
		Oauth: &supportv1.OAuthSupport{
			ModelCatalog: &supportv1.OAuthModelCatalog{
				AuthenticatedDiscovery: &supportv1.OAuthModelCatalogDiscovery{
					CollectorId:       "codex-oauth",
					AuthorityPriority: 650,
					Operation: &modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation{
						BaseUrl:      "https://chatgpt.com/backend-api/codex",
						Path:         "models",
						Method:       modelcatalogdiscoveryv1.DiscoveryHTTPMethod_DISCOVERY_HTTP_METHOD_GET,
						ResponseKind: modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_CODEX_MODELS,
					},
				},
			},
		},
	}

	configured, operation, err := ResolveOAuthModelCatalogDiscovery(pkg)
	if err != nil {
		t.Fatalf("ResolveOAuthModelCatalogDiscovery() error = %v", err)
	}
	if got, want := configured.GetCollectorId(), "codex-oauth"; got != want {
		t.Fatalf("collector_id = %q, want %q", got, want)
	}
	if got, want := operation.GetBaseUrl(), "https://chatgpt.com/backend-api/codex"; got != want {
		t.Fatalf("operation.base_url = %q, want %q", got, want)
	}
}

func TestResolveOAuthModelCatalogDiscoveryReturnsNilWhenUnconfigured(t *testing.T) {
	configured, operation, err := ResolveOAuthModelCatalogDiscovery(&supportv1.CLI{
		CliId: "claude-code",
		Oauth: &supportv1.OAuthSupport{},
	})
	if err != nil {
		t.Fatalf("ResolveOAuthModelCatalogDiscovery() error = %v", err)
	}
	if configured != nil {
		t.Fatalf("configured = %v, want nil", configured)
	}
	if operation != nil {
		t.Fatalf("operation = %v, want nil", operation)
	}
}

func testJWT(payload string) string {
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}
