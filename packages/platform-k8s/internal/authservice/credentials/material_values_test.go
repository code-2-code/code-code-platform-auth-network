package credentials

import (
	"testing"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	"code-code.internal/platform-k8s/internal/platform/testutil"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCredentialManagementServiceMergeMaterialValuesUpdatesOnlyExplicitKeys(t *testing.T) {
	t.Parallel()

	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(testCredentialResource("credential-gemini", credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH, 1, nil)).
		Build()
	materialStore := newMemoryCredentialMaterialStore(map[string]map[string]string{
		"credential-gemini": {
			"access_token": "token",
			"project_id":   "old-project",
		},
	})
	service, err := NewCredentialManagementService(client, "code-code", materialStore)
	if err != nil {
		t.Fatalf("NewCredentialManagementService() error = %v", err)
	}

	err = service.MergeMaterialValues(t.Context(), "credential-gemini", map[string]string{
		" project_id ": " new-project ",
		"tier_name":    "Google AI Pro",
		"":             "ignored",
		"blank":        " ",
	})
	if err != nil {
		t.Fatalf("MergeMaterialValues() error = %v", err)
	}

	values := materialStore.valuesForTest("credential-gemini")
	if got, want := values["access_token"], "token"; got != want {
		t.Fatalf("access_token = %q, want %q", got, want)
	}
	if got, want := values["project_id"], "new-project"; got != want {
		t.Fatalf("project_id = %q, want %q", got, want)
	}
	if got, want := values["tier_name"], "Google AI Pro"; got != want {
		t.Fatalf("tier_name = %q, want %q", got, want)
	}
	if _, exists := values["blank"]; exists {
		t.Fatal("blank value was persisted")
	}
}
