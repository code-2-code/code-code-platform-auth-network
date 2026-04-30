package support

import (
	"testing"

	apiprotocolv1 "code-code.internal/go-contract/api_protocol/v1"
	credentialv1 "code-code.internal/go-contract/credential/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

func TestResolveAuthMaterializationReturnsOAuthContract(t *testing.T) {
	t.Parallel()

	materialization, err := ResolveAuthMaterialization(&supportv1.CLI{
		CliId: "gemini-cli",
		Oauth: &supportv1.OAuthSupport{
			AuthMaterialization: testOAuthMaterialization(),
		},
	}, credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH, apiprotocolv1.Protocol_PROTOCOL_UNSPECIFIED)
	if err != nil {
		t.Fatalf("ResolveAuthMaterialization() error = %v", err)
	}
	if got, want := materialization.GetMaterializationKey(), "gemini-cli.google-oauth"; got != want {
		t.Fatalf("materialization_key = %q, want %q", got, want)
	}
}

func TestResolveAuthMaterializationReturnsAPIKeyContract(t *testing.T) {
	t.Parallel()

	materialization, err := ResolveAuthMaterialization(&supportv1.CLI{
		CliId: "claude-code",
		ApiKeyProtocols: []*supportv1.APIKeyProtocolSupport{{
			Protocol:            apiprotocolv1.Protocol_PROTOCOL_ANTHROPIC,
			DisplayName:         "Anthropic",
			AuthMaterialization: testAPIKeyMaterialization(),
		}},
	}, credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY, apiprotocolv1.Protocol_PROTOCOL_ANTHROPIC)
	if err != nil {
		t.Fatalf("ResolveAuthMaterialization() error = %v", err)
	}
	if got, want := materialization.GetRequestAuthInjection().GetHeaderNames()[0], "x-api-key"; got != want {
		t.Fatalf("header_names[0] = %q, want %q", got, want)
	}
}

func TestValidateAuthMaterializationsRejectsMissingInjection(t *testing.T) {
	t.Parallel()

	err := ValidateAuthMaterializations(&supportv1.CLI{
		CliId: "claude-code",
		ApiKeyProtocols: []*supportv1.APIKeyProtocolSupport{{
			Protocol: apiprotocolv1.Protocol_PROTOCOL_ANTHROPIC,
			AuthMaterialization: &supportv1.CLIAuthMaterialization{
				MaterializationKey:       "claude-code.anthropic-api-key",
				RuntimeUrlProjectionKind: supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_BASE_URL,
				IncludeRuntimeUrlHost:    true,
			},
		}},
	})
	if err == nil {
		t.Fatal("ValidateAuthMaterializations() error = nil, want validation error")
	}
}

func TestResolveTargetHostsIncludesBaseURLHostAndExtras(t *testing.T) {
	t.Parallel()

	hosts, err := ResolveTargetHosts(&supportv1.CLIAuthMaterialization{
		RuntimeUrlProjectionKind: supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_BASE_URL,
		IncludeRuntimeUrlHost:    true,
		ExtraTargetHosts:         []string{"oauth2.googleapis.com", "www.googleapis.com"},
		RequestAuthInjection: &supportv1.RequestAuthInjection{
			HeaderNames: []string{"authorization"},
		},
		MaterializationKey: "gemini-cli.google-oauth",
	}, "https://cloudcode-pa.googleapis.com/v1")
	if err != nil {
		t.Fatalf("ResolveTargetHosts() error = %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("target_hosts = %d, want 3", len(hosts))
	}
}

func TestResolveTargetPathPrefixesUsesExplicitPathsOrRuntimeURLPath(t *testing.T) {
	t.Parallel()

	explicit, err := ResolveTargetPathPrefixes(&supportv1.CLIAuthMaterialization{
		TargetPathPrefixes:       []string{"v1internal", "/v1internal/"},
		RuntimeUrlProjectionKind: supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_BASE_URL,
		IncludeRuntimeUrlHost:    true,
		RequestAuthInjection: &supportv1.RequestAuthInjection{
			HeaderNames: []string{"authorization"},
		},
		MaterializationKey: "gemini-cli.google-oauth",
	}, "https://cloudcode-pa.googleapis.com/ignored")
	if err != nil {
		t.Fatalf("ResolveTargetPathPrefixes() explicit error = %v", err)
	}
	if got, want := explicit, []string{"/v1internal"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("explicit target_path_prefixes = %v, want %v", got, want)
	}
	inferred, err := ResolveTargetPathPrefixes(&supportv1.CLIAuthMaterialization{
		RuntimeUrlProjectionKind: supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_BASE_URL,
		IncludeRuntimeUrlHost:    true,
		RequestAuthInjection: &supportv1.RequestAuthInjection{
			HeaderNames: []string{"authorization"},
		},
		MaterializationKey: "codex.openai-oauth",
	}, "https://api.openai.com/v1")
	if err != nil {
		t.Fatalf("ResolveTargetPathPrefixes() inferred error = %v", err)
	}
	if got, want := inferred, []string{"/v1"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("inferred target_path_prefixes = %v, want %v", got, want)
	}
}

func testOAuthMaterialization() *supportv1.CLIAuthMaterialization {
	return &supportv1.CLIAuthMaterialization{
		MaterializationKey:       "gemini-cli.google-oauth",
		RuntimeUrlProjectionKind: supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_BASE_URL,
		ExtraTargetHosts:         []string{"oauth2.googleapis.com", "www.googleapis.com"},
		RequestAuthInjection: &supportv1.RequestAuthInjection{
			HeaderNames:       []string{"authorization"},
			HeaderValuePrefix: "Bearer ",
		},
	}
}

func testAPIKeyMaterialization() *supportv1.CLIAuthMaterialization {
	return &supportv1.CLIAuthMaterialization{
		MaterializationKey:       "claude-code.anthropic-api-key",
		RuntimeUrlProjectionKind: supportv1.RuntimeProjectionKind_RUNTIME_PROJECTION_KIND_BASE_URL,
		IncludeRuntimeUrlHost:    true,
		RequestAuthInjection: &supportv1.RequestAuthInjection{
			HeaderNames: []string{"x-api-key"},
		},
	}
}
