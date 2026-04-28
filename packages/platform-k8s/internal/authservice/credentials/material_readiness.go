package credentials

import (
	"context"
	"fmt"
	"strings"

	credentialcontract "code-code.internal/agent-runtime-contract/credential"
	credentialv1 "code-code.internal/go-contract/credential/v1"
	"code-code.internal/go-contract/domainerror"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const ConditionCredentialMaterialReady = "MaterialReady"

// MaterialReadinessReader validates credential-owned material readiness.
type MaterialReadinessReader struct {
	client        ctrlclient.Client
	namespace     string
	materialStore CredentialMaterialStore
}

func NewMaterialReadinessReaderWithStore(client ctrlclient.Client, namespace string, materialStore CredentialMaterialStore) (*MaterialReadinessReader, error) {
	if client == nil {
		return nil, fmt.Errorf("credentials: material readiness client is nil")
	}
	if strings.TrimSpace(namespace) == "" {
		return nil, fmt.Errorf("credentials: material readiness namespace is empty")
	}
	if materialStore == nil {
		return nil, fmt.Errorf("credentials: material readiness material store is nil")
	}
	return &MaterialReadinessReader{
		client:        client,
		namespace:     strings.TrimSpace(namespace),
		materialStore: materialStore,
	}, nil
}

// ValidateReady checks whether one credential currently exposes usable auth material.
func (r *MaterialReadinessReader) ValidateReady(ctx context.Context, ref *credentialcontract.CredentialRef) error {
	resource, err := r.getCredentialResource(ctx, ref)
	if err != nil {
		return err
	}
	if condition := currentMaterialReadyCondition(resource); condition != nil {
		if condition.Status == metav1.ConditionTrue {
			return nil
		}
		message := strings.TrimSpace(condition.Message)
		if message == "" {
			message = "credential auth material is not ready"
		}
		return domainerror.NewValidation(
			"credentials: credential %q material is not ready: %s",
			resource.GetName(),
			message,
		)
	}
	return validateCredentialResourceMaterial(ctx, r.materialStore, resource)
}

func (r *MaterialReadinessReader) getCredentialResource(ctx context.Context, ref *credentialcontract.CredentialRef) (*platformv1alpha1.CredentialDefinitionResource, error) {
	if err := credentialv1.ValidateRef(ref); err != nil {
		return nil, err
	}
	resource := &platformv1alpha1.CredentialDefinitionResource{}
	key := types.NamespacedName{Namespace: r.namespace, Name: ref.GetCredentialId()}
	if err := r.client.Get(ctx, key, resource); err != nil {
		return nil, mapCredentialGetError(ref.GetCredentialId(), err)
	}
	return resource, nil
}

func currentMaterialReadyCondition(resource *platformv1alpha1.CredentialDefinitionResource) *metav1.Condition {
	if resource == nil {
		return nil
	}
	condition := meta.FindStatusCondition(resource.Status.Conditions, ConditionCredentialMaterialReady)
	if condition == nil {
		return nil
	}
	if condition.ObservedGeneration != resource.GetGeneration() {
		return nil
	}
	return condition
}

func validateCredentialResourceMaterial(
	ctx context.Context,
	materialStore CredentialMaterialStore,
	resource *platformv1alpha1.CredentialDefinitionResource,
) error {
	if resource == nil {
		return domainerror.NewValidation("credentials: credential resource is nil")
	}
	definition, err := credentialsDefinitionFromResource(resource)
	if err != nil {
		return err
	}
	if materialStore == nil {
		return domainerror.NewValidation("credentials: credential material store is nil")
	}
	values, err := materialStore.ReadValues(ctx, definition.GetCredentialId())
	if err != nil {
		return mapCredentialMaterialGetError(definition.GetCredentialId(), err)
	}
	resolved, err := resolveFromValues(definition, values, resource.Status.OAuth)
	if err != nil {
		return err
	}
	if err := credentialv1.ValidateResolvedCredential(resolved); err != nil {
		return domainerror.NewValidation("credentials: invalid resolved credential %q: %v", definition.GetCredentialId(), err)
	}
	return nil
}

func mapCredentialGetError(credentialID string, err error) error {
	if apierrors.IsNotFound(err) {
		return domainerror.NewNotFound("credentials: credential %q not found", credentialID)
	}
	return fmt.Errorf("credentials: get credential %q: %w", credentialID, err)
}

func mapCredentialMaterialGetError(credentialID string, err error) error {
	if apierrors.IsNotFound(err) {
		return domainerror.NewValidation("credentials: material not found for credential %q", credentialID)
	}
	return fmt.Errorf("credentials: read credential material %q: %w", credentialID, err)
}
