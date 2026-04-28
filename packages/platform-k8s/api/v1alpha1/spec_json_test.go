package v1alpha1

import (
	"encoding/json"
	"strings"
	"testing"

	credentialv1 "code-code.internal/go-contract/credential/v1"
)

func TestCredentialDefinitionSpecJSONUsesProtoJSONNames(t *testing.T) {
	spec := CredentialDefinitionResourceSpec{
		Definition: &credentialv1.CredentialDefinition{
			CredentialId: "credential-codex",
			DisplayName:  "Codex",
			Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
			KindMetadata: &credentialv1.CredentialDefinition_OauthMetadata{
				OauthMetadata: &credentialv1.OAuthMetadata{
					CliId: "codex",
				},
			},
		},
	}

	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	body := string(raw)
	for _, expected := range []string{`"credentialId"`, `"displayName"`, `"oauthMetadata"`, `"cliId"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected %s in %s", expected, body)
		}
	}
	for _, unexpected := range []string{`"credential_id"`, `"display_name"`, `"KindMetadata"`, `"OauthMetadata"`, `"secretSource"`} {
		if strings.Contains(body, unexpected) {
			t.Fatalf("did not expect %s in %s", unexpected, body)
		}
	}
}
