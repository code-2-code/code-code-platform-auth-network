package credentials

import (
	"context"
	"testing"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestResolverResolveAPIKeyCredential(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	if err := platformv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&platformv1alpha1.CredentialDefinitionResource{
				ObjectMeta: metav1.ObjectMeta{Name: "openai-key", Namespace: "control-plane"},
				Spec: platformv1alpha1.CredentialDefinitionResourceSpec{
					Definition: &credentialv1.CredentialDefinition{
						DisplayName: "OpenAI Key",
						Kind:        credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY,
					},
				},
			},
		).
		Build()

	materialStore := newMemoryCredentialMaterialStore(map[string]map[string]string{
		"openai-key": {"api_key": "secret-value"},
	})
	resolver, err := NewResolver(client, "control-plane", materialStore)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	resolved, err := resolver.Resolve(context.Background(), &credentialv1.CredentialRef{CredentialId: "openai-key"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got, want := resolved.GetApiKey().ApiKey, "secret-value"; got != want {
		t.Fatalf("api key = %q, want %q", got, want)
	}
	if resolved.GetApiKey() == nil {
		t.Fatal("api key material = nil")
	}
}
