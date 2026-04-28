package credentials

import (
	"testing"

	credentialv1 "code-code.internal/go-contract/credential/v1"
)

func TestCredentialResourceAndMaterialValuesStoreAPIKeyMaterial(t *testing.T) {
	t.Parallel()

	credential, err := NewCredential(
		&credentialv1.CredentialDefinition{
			CredentialId: "custom-key",
			DisplayName:  "Custom Key",
			Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY,
			Purpose:      credentialv1.CredentialPurpose_CREDENTIAL_PURPOSE_DATA_PLANE,
			VendorId:     "custom",
		},
		&credentialv1.ResolvedCredential{
			CredentialId: "custom-key",
			Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY,
			Material: &credentialv1.ResolvedCredential_ApiKey{
				ApiKey: &credentialv1.ApiKeyCredential{ApiKey: "secret"},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}

	resource := credential.Resource("control-plane")
	values, err := credential.MaterialValues()
	if err != nil {
		t.Fatalf("MaterialValues() error = %v", err)
	}
	if resource.Spec.Definition.GetOauthMetadata() != nil {
		t.Fatal("oauth_metadata = non-nil, want nil for api key credential")
	}
	if got, want := values["api_key"], "secret"; got != want {
		t.Fatalf("api_key = %q, want %q", got, want)
	}
}
