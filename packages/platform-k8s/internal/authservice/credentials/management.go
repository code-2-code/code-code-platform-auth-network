package credentials

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	"code-code.internal/go-contract/domainerror"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// CredentialManagementService manages credential resources.
type CredentialManagementService struct {
	client        ctrlclient.Client
	namespace     string
	store         ResourceStore
	materialStore CredentialMaterialStore
}

type CredentialReferenceChecker interface {
	CheckCredentialReferences(ctx context.Context, credentialID string) error
}

// NewCredentialManagementService creates one credential management service.
func NewCredentialManagementService(
	client ctrlclient.Client,
	namespace string,
	materialStore CredentialMaterialStore,
) (*CredentialManagementService, error) {
	if client == nil {
		return nil, fmt.Errorf("platformk8s: client is nil")
	}
	if namespace == "" {
		return nil, fmt.Errorf("platformk8s: namespace is empty")
	}
	store, err := NewKubernetesResourceStore(client, namespace)
	if err != nil {
		return nil, err
	}
	return NewCredentialManagementServiceWithStores(client, namespace, store, materialStore)
}

func NewCredentialManagementServiceWithStores(
	client ctrlclient.Client,
	namespace string,
	store ResourceStore,
	materialStore CredentialMaterialStore,
) (*CredentialManagementService, error) {
	if client == nil {
		return nil, fmt.Errorf("platformk8s: client is nil")
	}
	if namespace == "" {
		return nil, fmt.Errorf("platformk8s: namespace is empty")
	}
	if store == nil {
		return nil, fmt.Errorf("platformk8s: credential resource store is nil")
	}
	if materialStore == nil {
		return nil, fmt.Errorf("platformk8s: credential material store is nil")
	}
	return &CredentialManagementService{client: client, namespace: namespace, store: store, materialStore: materialStore}, nil
}

// List returns all credential resources in UI-facing form.
func (s *CredentialManagementService) List(ctx context.Context) ([]*managementv1.CredentialView, error) {
	items, err := s.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: list credentials: %w", err)
	}

	views := make([]*managementv1.CredentialView, 0, len(items))
	for i := range items {
		view, err := s.credentialResourceToView(ctx, &items[i])
		if err != nil {
			slog.Warn("skip invalid credential list item", "name", items[i].GetName(), "error", err)
			continue
		}
		views = append(views, view)
	}
	slices.SortFunc(views, func(a, b *managementv1.CredentialView) int {
		if a.GetDisplayName() < b.GetDisplayName() {
			return -1
		}
		if a.GetDisplayName() > b.GetDisplayName() {
			return 1
		}
		if a.GetCredentialId() < b.GetCredentialId() {
			return -1
		}
		if a.GetCredentialId() > b.GetCredentialId() {
			return 1
		}
		return 0
	})
	return views, nil
}

func (s *CredentialManagementService) Exists(ctx context.Context, credentialID string) (bool, error) {
	if s == nil {
		return false, fmt.Errorf("platformk8s: credential service is nil")
	}
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return false, domainerror.NewValidation("platformk8s: credential id is empty")
	}
	_, err := s.store.Get(ctx, credentialID)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("platformk8s: get credential %q: %w", credentialID, err)
	}
	return true, nil
}

func (s *CredentialManagementService) ReadDefinition(ctx context.Context, credentialID string) (*credentialv1.CredentialDefinition, error) {
	if s == nil {
		return nil, fmt.Errorf("platformk8s: credential service is nil")
	}
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return nil, domainerror.NewValidation("platformk8s: credential id is empty")
	}
	resource, err := s.store.Get(ctx, credentialID)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: get credential %q: %w", credentialID, err)
	}
	return credentialsDefinitionFromResource(resource)
}

func (s *CredentialManagementService) UpdateDisplayName(ctx context.Context, credentialID, displayName string) error {
	if s == nil {
		return fmt.Errorf("platformk8s: credential service is nil")
	}
	credentialID = strings.TrimSpace(credentialID)
	displayName = strings.TrimSpace(displayName)
	if credentialID == "" {
		return domainerror.NewValidation("platformk8s: credential id is empty")
	}
	if displayName == "" {
		return domainerror.NewValidation("platformk8s: credential display name is empty")
	}
	return s.store.Update(ctx, credentialID, func(current *platformv1alpha1.CredentialDefinitionResource) error {
		if current.Spec.Definition == nil {
			return domainerror.NewValidation("platformk8s: credential resource %q is missing definition", credentialID)
		}
		current.Spec.Definition.DisplayName = displayName
		return nil
	})
}

// Delete removes one credential and its backing material after verifying no
// other resource references it.
func (s *CredentialManagementService) Delete(ctx context.Context, credentialID string, refChecker CredentialReferenceChecker) error {
	if credentialID == "" {
		return domainerror.NewValidation("platformk8s: credential id is empty")
	}
	if refChecker != nil {
		if err := refChecker.CheckCredentialReferences(ctx, credentialID); err != nil {
			return err
		}
	}
	if err := s.store.Delete(ctx, credentialID); err != nil {
		return err
	}
	return s.materialStore.DeleteValues(ctx, credentialID)
}

// Update updates one existing credential and its backing material.
func (s *CredentialManagementService) Update(ctx context.Context, credentialID string, credential *Credential) (*managementv1.CredentialView, error) {
	if credential == nil {
		return nil, domainerror.NewValidation("platformk8s/credentials: credential is nil")
	}
	if credential.ID() != "" && credential.ID() != credentialID {
		return nil, domainerror.NewValidation(
			"platformk8s/credentials: path credential id %q does not match payload %q",
			credentialID,
			credential.ID(),
		)
	}
	next := credential.WithID(credentialID)
	currentValues, err := s.materialStore.ReadValues(ctx, credentialID)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("platformk8s: read credential material %q: %w", credentialID, err)
		}
	}
	if len(currentValues) > 0 {
		next.PreserveMissingMaterialValues(currentValues)
	}
	resource := next.Resource(s.namespace)
	values, err := next.MaterialValues()
	if err != nil {
		return nil, err
	}
	if err := s.materialStore.WriteValues(ctx, resource.Name, values); err != nil {
		return nil, err
	}
	if err := s.store.Upsert(ctx, resource); err != nil {
		return nil, err
	}
	return s.credentialResourceToView(ctx, resource)
}

func credentialsDefinitionFromResource(resource *platformv1alpha1.CredentialDefinitionResource) (*credentialv1.CredentialDefinition, error) {
	if resource == nil || resource.Spec.Definition == nil {
		return nil, domainerror.NewValidation("platformk8s: credential resource is invalid")
	}
	if err := credentialv1.ValidateDefinition(resource.Spec.Definition); err != nil {
		return nil, domainerror.NewValidation("platformk8s: invalid credential definition %q: %v", resource.Name, err)
	}
	return resource.Spec.Definition, nil
}
