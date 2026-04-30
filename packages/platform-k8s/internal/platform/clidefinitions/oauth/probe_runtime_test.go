package oauth

import (
	"context"
	"net/http"
	"testing"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	modelv1 "code-code.internal/go-contract/model/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	providerv1 "code-code.internal/go-contract/provider/v1"
	"code-code.internal/platform-k8s/internal/cliruntimeservice/cliversions"
)

func TestApplyOAuthProbeClientIdentityHeaders(t *testing.T) {
	headers := ApplyOAuthProbeClientIdentityHeaders(http.Header{}, &supportv1.CLI{
		CliId: "antigravity",
		Oauth: &supportv1.OAuthSupport{
			ClientIdentity: &supportv1.OAuthClientIdentity{
				ModelCatalogUserAgentTemplate: "antigravity/${client_version} darwin/arm64",
			},
		},
	}, "1.22.2")
	if got, want := headers.Get("User-Agent"), "antigravity/1.22.2 darwin/arm64"; got != want {
		t.Fatalf("user-agent = %q, want %q", got, want)
	}
}

func TestBuildOAuthProbeCatalog(t *testing.T) {
	catalog, err := BuildOAuthProbeCatalog(testProbePackage(), []string{"gpt-5.4", "gpt-5.4"}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("BuildOAuthProbeCatalog() error = %v", err)
	}
	if got, want := catalog.GetSource(), providerv1.CatalogSource_CATALOG_SOURCE_PROTOCOL_QUERY; got != want {
		t.Fatalf("catalog source = %v, want %v", got, want)
	}
	if got, want := len(catalog.GetModels()), 1; got != want {
		t.Fatalf("len(models) = %d, want %d", got, want)
	}
	if got, want := catalog.GetModels()[0].GetModelRef().GetVendorId(), "openai"; got != want {
		t.Fatalf("model_ref.vendor_id = %q, want %q", got, want)
	}
}

func TestBuildOAuthProbeCatalogPrefersFallbackMetadata(t *testing.T) {
	catalog, err := BuildOAuthProbeCatalog(&supportv1.CLI{
		CliId:    "gemini-cli",
		VendorId: "google",
		Oauth: &supportv1.OAuthSupport{
			ModelCatalog: &supportv1.OAuthModelCatalog{
				DefaultCatalog: &providerv1.ProviderModelCatalog{
					Models: []*providerv1.ProviderModelCatalogEntry{
						{
							ProviderModelId: "gemini-2.5-pro",
							ModelRef:        &modelv1.ModelRef{VendorId: "google", ModelId: "gemini-2.5-pro"},
						},
						{
							ProviderModelId: "gemini-3-pro-preview",
							ModelRef:        &modelv1.ModelRef{VendorId: "google", ModelId: "gemini-3-pro-preview"},
						},
					},
				},
			},
		},
	}, []string{"gemini-3-pro-preview"}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("BuildOAuthProbeCatalog() error = %v", err)
	}
	if got, want := len(catalog.GetModels()), 1; got != want {
		t.Fatalf("len(models) = %d, want %d", got, want)
	}
	if got, want := catalog.GetModels()[0].GetProviderModelId(), "gemini-3-pro-preview"; got != want {
		t.Fatalf("provider_model_id = %q, want %q", got, want)
	}
	if got, want := catalog.GetModels()[0].GetModelRef().GetModelId(), "gemini-3-pro-preview"; got != want {
		t.Fatalf("model_ref.model_id = %q, want %q", got, want)
	}
}

func TestBuildOAuthProbeCatalogFiltersAntigravityOpaqueProbeModels(t *testing.T) {
	catalog, err := BuildOAuthProbeCatalog(&supportv1.CLI{
		CliId:    "antigravity",
		VendorId: "google",
		Oauth: &supportv1.OAuthSupport{
			ModelCatalog: &supportv1.OAuthModelCatalog{
				DefaultCatalog: &providerv1.ProviderModelCatalog{
					Models: []*providerv1.ProviderModelCatalogEntry{
						{
							ProviderModelId: "gemini-2.5-pro",
							ModelRef:        &modelv1.ModelRef{VendorId: "google", ModelId: "gemini-2.5-pro"},
						},
					},
				},
			},
		},
	}, []string{
		"chat_20706",
		"gemini-2.5-pro",
		"gemini-3-pro-high",
		"claude-sonnet-4-6",
		"tab_flash_lite_preview",
	}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("BuildOAuthProbeCatalog() error = %v", err)
	}
	if got, want := len(catalog.GetModels()), 3; got != want {
		t.Fatalf("len(models) = %d, want %d", got, want)
	}
	if got, want := catalog.GetModels()[0].GetProviderModelId(), "gemini-2.5-pro"; got != want {
		t.Fatalf("models[0].provider_model_id = %q, want %q", got, want)
	}
	if got, want := catalog.GetModels()[1].GetModelRef().GetModelId(), "gemini-3-pro-high"; got != want {
		t.Fatalf("models[1].model_ref.model_id = %q, want %q", got, want)
	}
	if got, want := catalog.GetModels()[2].GetModelRef().GetModelId(), "claude-sonnet-4-6"; got != want {
		t.Fatalf("models[2].model_ref.model_id = %q, want %q", got, want)
	}
}

func TestResolveOAuthDiscoveryDynamicValues(t *testing.T) {
	versionStore := staticVersionStore{state: &cliversions.State{
		Versions: map[string]cliversions.Snapshot{
			"codex": {Version: "1.2.3"},
		},
	}}

	values, err := ResolveOAuthDiscoveryDynamicValues(context.Background(), versionStore, "codex")
	if err != nil {
		t.Fatalf("ResolveOAuthDiscoveryDynamicValues() error = %v", err)
	}
	if got, want := values.ClientVersion, "1.2.3"; got != want {
		t.Fatalf("client_version = %q, want %q", got, want)
	}
}

type staticVersionStore struct {
	state *cliversions.State
}

func (s staticVersionStore) Load(context.Context) (*cliversions.State, error) {
	return s.state, nil
}

func (s staticVersionStore) Save(context.Context, *cliversions.State) error {
	return nil
}

func testProbePackage() *supportv1.CLI {
	return &supportv1.CLI{
		CliId:    "codex",
		VendorId: "openai",
		Oauth: &supportv1.OAuthSupport{
			Flow: credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_CODE,
			AuthMaterialization: &supportv1.CLIAuthMaterialization{
				MaterializationKey:       "codex.openai-oauth",
				RuntimeUrlProjectionKind: supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_BASE_URL,
				IncludeRuntimeUrlHost:    true,
				RequestAuthInjection: &supportv1.RequestAuthInjection{
					HeaderNames:       []string{http.CanonicalHeaderKey("authorization")},
					HeaderValuePrefix: "Bearer ",
				},
			},
		},
	}
}
