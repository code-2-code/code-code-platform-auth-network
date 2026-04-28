package credentials

import (
	"strings"
	"testing"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"code-code.internal/platform-k8s/internal/platform/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCredentialManagementServiceListProjectsMaterialStatus(t *testing.T) {
	t.Parallel()

	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(testCredentialResource("provider-key", credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY, 2, []metav1.Condition{{
			Type:               ConditionCredentialMaterialReady,
			Status:             metav1.ConditionFalse,
			Reason:             "MaterialInvalid",
			Message:            "credential material missing",
			ObservedGeneration: 2,
		}})).
		Build()
	service, err := NewCredentialManagementService(client, "code-code", newMemoryCredentialMaterialStore(nil))
	if err != nil {
		t.Fatalf("NewCredentialManagementService() error = %v", err)
	}

	items, err := service.List(t.Context())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := len(items), 1; got != want {
		t.Fatalf("len(items) = %d, want %d", got, want)
	}
	if items[0].GetStatus().GetMaterialReady() {
		t.Fatal("materialReady = true, want false")
	}
	if got, want := items[0].GetStatus().GetReason(), "credential material missing"; got != want {
		t.Fatalf("reason = %q, want %q", got, want)
	}
}

func TestCredentialManagementServiceCreateReturnsReadyStatus(t *testing.T) {
	t.Parallel()

	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		Build()
	service, err := NewCredentialManagementService(client, "code-code", newMemoryCredentialMaterialStore(nil))
	if err != nil {
		t.Fatalf("NewCredentialManagementService() error = %v", err)
	}

	credential, err := NewCredential(
		&credentialv1.CredentialDefinition{
			DisplayName: "OpenAI Key",
			Kind:        credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY,
			Purpose:     credentialv1.CredentialPurpose_CREDENTIAL_PURPOSE_DATA_PLANE,
		},
		&credentialv1.ResolvedCredential{
			Kind: credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY,
			Material: &credentialv1.ResolvedCredential_ApiKey{
				ApiKey: &credentialv1.ApiKeyCredential{
					ApiKey: "sk-live",
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}

	view, err := service.Create(t.Context(), credential)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !view.GetStatus().GetMaterialReady() {
		t.Fatal("materialReady = false, want true")
	}
	if got := strings.TrimSpace(view.GetStatus().GetReason()); got != "" {
		t.Fatalf("reason = %q, want empty", got)
	}
}

func TestCredentialManagementServiceListSkipsInvalidCredentialResource(t *testing.T) {
	t.Parallel()

	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(
			testCredentialResource("valid-credential", credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY, 1, nil),
			&platformv1alpha1.CredentialDefinitionResource{
				TypeMeta: metav1.TypeMeta{
					APIVersion: platformv1alpha1.GroupVersion.String(),
					Kind:       platformv1alpha1.KindCredentialDefinitionResource,
				},
				ObjectMeta: metav1.ObjectMeta{Name: "broken-credential", Namespace: "code-code"},
				Spec:       platformv1alpha1.CredentialDefinitionResourceSpec{},
			},
		).
		Build()
	service, err := NewCredentialManagementService(client, "code-code", newMemoryCredentialMaterialStore(map[string]map[string]string{
		"valid-credential": {materialKeyAPIKey: "secret"},
	}))
	if err != nil {
		t.Fatalf("NewCredentialManagementService() error = %v", err)
	}

	items, err := service.List(t.Context())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := len(items), 1; got != want {
		t.Fatalf("len(items) = %d, want %d", got, want)
	}
	if got, want := items[0].GetCredentialId(), "valid-credential"; got != want {
		t.Fatalf("credentialId = %q, want %q", got, want)
	}
}

func TestCredentialManagementServiceListProjectsOAuthAccountEmailFromMaterial(t *testing.T) {
	t.Parallel()

	const credentialID = "gemini-cli-credential"
	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(
			testCredentialResource(
				credentialID,
				credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
				1,
				[]metav1.Condition{{
					Type:               ConditionCredentialMaterialReady,
					Status:             metav1.ConditionTrue,
					Reason:             "MaterialResolved",
					ObservedGeneration: 1,
				}},
			),
		).
		Build()
	service, err := NewCredentialManagementService(client, "code-code", newMemoryCredentialMaterialStore(map[string]map[string]string{
		credentialID: {
			materialKeyAccessToken:  "access-token",
			materialKeyExpiresAt:    "2026-04-16T12:00:00Z",
			materialKeyAccountEmail: "playerfoxme@gmail.com",
		},
	}))
	if err != nil {
		t.Fatalf("NewCredentialManagementService() error = %v", err)
	}

	items, err := service.List(t.Context())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := len(items), 1; got != want {
		t.Fatalf("len(items) = %d, want %d", got, want)
	}
	if got, want := items[0].GetAccountEmail(), "playerfoxme@gmail.com"; got != want {
		t.Fatalf("accountEmail = %q, want %q", got, want)
	}
}
