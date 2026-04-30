package support

import (
	"testing"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

func TestValidateOAuthClientIdentityAcceptsOfficialVersionSource(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "codex",
		OfficialVersionSource: &supportv1.OfficialVersionSource{
			Source: &supportv1.OfficialVersionSource_NpmDistTag{
				NpmDistTag: &supportv1.NPMRegistryVersionSource{
					PackageName: "@openai/codex",
					DistTag:     "latest",
				},
			},
		},
		Oauth: &supportv1.OAuthSupport{
			ClientIdentity: &supportv1.OAuthClientIdentity{
				ObservabilityUserAgentTemplate: "codex_cli_rs/${client_version}",
			},
		},
	}
	if err := ValidateOAuthClientIdentity(pkg); err != nil {
		t.Fatalf("ValidateOAuthClientIdentity() error = %v", err)
	}
}

func TestValidateOAuthClientIdentityRejectsMissingSourceForTemplate(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "codex",
		Oauth: &supportv1.OAuthSupport{
			ClientIdentity: &supportv1.OAuthClientIdentity{
				ObservabilityUserAgentTemplate: "codex_cli_rs/${client_version}",
			},
		},
	}
	if err := ValidateOAuthClientIdentity(pkg); err == nil {
		t.Fatal("ValidateOAuthClientIdentity() error = nil, want error")
	}
}

func TestValidateOAuthClientIdentityRejectsUnsupportedTemplateVariable(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "antigravity",
		OfficialVersionSource: &supportv1.OfficialVersionSource{
			Source: &supportv1.OfficialVersionSource_HomebrewCask{
				HomebrewCask: &supportv1.HomebrewCaskVersionSource{Cask: "antigravity"},
			},
		},
		Oauth: &supportv1.OAuthSupport{
			ClientIdentity: &supportv1.OAuthClientIdentity{
				ModelCatalogUserAgentTemplate: "antigravity/${platform}",
			},
		},
	}
	if err := ValidateOAuthClientIdentity(pkg); err == nil {
		t.Fatal("ValidateOAuthClientIdentity() error = nil, want error")
	}
}
