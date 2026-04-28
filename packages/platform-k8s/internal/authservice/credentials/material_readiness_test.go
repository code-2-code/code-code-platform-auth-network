package credentials

import (
	"strings"
	"testing"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"code-code.internal/platform-k8s/internal/platform/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestMaterialReadinessReaderValidateReadyAPIKey(t *testing.T) {
	t.Parallel()

	reader := newMaterialReadinessReaderForTest(t,
		map[string]map[string]string{"provider-key": {"api_key": "secret-value"}},
		testCredentialResource("provider-key", credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY, 1, nil),
	)

	if err := reader.ValidateReady(t.Context(), &credentialv1.CredentialRef{CredentialId: "provider-key"}); err != nil {
		t.Fatalf("ValidateReady() error = %v", err)
	}
}

func TestMaterialReadinessReaderFallsBackWhenConditionIsStale(t *testing.T) {
	t.Parallel()

	reader := newMaterialReadinessReaderForTest(t,
		map[string]map[string]string{"provider-key": {"api_key": "secret-value"}},
		testCredentialResource("provider-key", credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY, 2, []metav1.Condition{{
			Type:               ConditionCredentialMaterialReady,
			Status:             metav1.ConditionFalse,
			Reason:             "MaterialInvalid",
			Message:            "stale",
			ObservedGeneration: 1,
		}}),
	)

	if err := reader.ValidateReady(t.Context(), &credentialv1.CredentialRef{CredentialId: "provider-key"}); err != nil {
		t.Fatalf("ValidateReady() error = %v", err)
	}
}

func TestMaterialReadinessReaderUsesCurrentCondition(t *testing.T) {
	t.Parallel()

	reader := newMaterialReadinessReaderForTest(t,
		map[string]map[string]string{"provider-key": {"api_key": "secret-value"}},
		testCredentialResource("provider-key", credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY, 2, []metav1.Condition{{
			Type:               ConditionCredentialMaterialReady,
			Status:             metav1.ConditionFalse,
			Reason:             "MaterialInvalid",
			Message:            "credential auth material is stale",
			ObservedGeneration: 2,
		}}),
	)

	err := reader.ValidateReady(t.Context(), &credentialv1.CredentialRef{CredentialId: "provider-key"})
	if err == nil {
		t.Fatal("ValidateReady() error = nil, want current condition failure")
	}
	if !strings.Contains(err.Error(), "stale") {
		t.Fatalf("error = %q, want current condition message", err)
	}
}

func TestMaterialReadinessReaderRejectsBrokenOAuthMaterial(t *testing.T) {
	t.Parallel()

	reader := newMaterialReadinessReaderForTest(t,
		map[string]map[string]string{"oauth-credential": {"token_type": "Bearer"}},
		testCredentialResource("oauth-credential", credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH, 1, nil),
	)

	err := reader.ValidateReady(t.Context(), &credentialv1.CredentialRef{CredentialId: "oauth-credential"})
	if err == nil {
		t.Fatal("ValidateReady() error = nil, want oauth material validation failure")
	}
	if !strings.Contains(err.Error(), "access_token") {
		t.Fatalf("error = %q, want access_token validation error", err)
	}
}

func newMaterialReadinessReaderForTest(t *testing.T, material map[string]map[string]string, objects ...ctrlclient.Object) *MaterialReadinessReader {
	t.Helper()

	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(objects...).
		Build()
	reader, err := NewMaterialReadinessReaderWithStore(client, "code-code", newMemoryCredentialMaterialStore(material))
	if err != nil {
		t.Fatalf("NewMaterialReadinessReader() error = %v", err)
	}
	return reader
}

func testCredentialResource(
	name string,
	kind credentialv1.CredentialKind,
	generation int64,
	conditions []metav1.Condition,
) *platformv1alpha1.CredentialDefinitionResource {
	return &platformv1alpha1.CredentialDefinitionResource{
		TypeMeta: metav1.TypeMeta{
			APIVersion: platformv1alpha1.GroupVersion.String(),
			Kind:       platformv1alpha1.KindCredentialDefinitionResource,
		},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "code-code", Generation: generation},
		Spec: platformv1alpha1.CredentialDefinitionResourceSpec{
			Definition: &credentialv1.CredentialDefinition{
				CredentialId: name,
				DisplayName:  name,
				Kind:         kind,
			},
		},
		Status: platformv1alpha1.CredentialDefinitionResourceStatus{
			CommonStatusFields: platformv1alpha1.CommonStatusFields{Conditions: conditions},
		},
	}
}
