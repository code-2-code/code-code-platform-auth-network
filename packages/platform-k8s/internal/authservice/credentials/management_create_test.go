package credentials

import (
	"testing"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	"code-code.internal/platform-k8s/internal/platform/testutil"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCredentialManagementServiceCreateDoesNotWriteMaterialWhenResourceCreateFails(t *testing.T) {
	t.Parallel()

	const credentialID = "openai-credential"
	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(testCredentialResource(credentialID, credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY, 1, nil)).
		Build()
	materialStore := newMemoryCredentialMaterialStore(nil)
	service, err := NewCredentialManagementService(client, "code-code", materialStore)
	if err != nil {
		t.Fatalf("NewCredentialManagementService() error = %v", err)
	}
	credential, err := NewCredential(
		&credentialv1.CredentialDefinition{
			CredentialId: credentialID,
			DisplayName:  "OpenAI",
			Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY,
			Purpose:      credentialv1.CredentialPurpose_CREDENTIAL_PURPOSE_DATA_PLANE,
		},
		&credentialv1.ResolvedCredential{
			Kind: credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY,
			Material: &credentialv1.ResolvedCredential_ApiKey{
				ApiKey: &credentialv1.ApiKeyCredential{ApiKey: "sk-openai"},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}

	if _, err := service.Create(t.Context(), credential); err == nil {
		t.Fatal("Create() error = nil, want already exists")
	}
	if values := materialStore.valuesForTest(credentialID); len(values) != 0 {
		t.Fatalf("material values = %v, want empty", values)
	}
}
