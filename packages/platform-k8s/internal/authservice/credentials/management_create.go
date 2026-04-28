package credentials

import (
	"context"
	"errors"
	"fmt"

	"code-code.internal/go-contract/domainerror"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Create stores one new credential and its backing material.
func (s *CredentialManagementService) Create(ctx context.Context, credential *Credential) (*managementv1.CredentialView, error) {
	if credential == nil {
		return nil, domainerror.NewValidation("platformk8s/credentials: credential is nil")
	}
	resource := credential.Resource(s.namespace)
	values, err := credential.MaterialValues()
	if err != nil {
		return nil, err
	}
	if err := s.store.Create(ctx, resource); err != nil {
		err = classifyCredentialCreateError(err, resource.Spec.Definition.CredentialId)
		return nil, err
	}
	if err := s.materialStore.WriteValues(ctx, resource.Name, values); err != nil {
		err = errors.Join(err, s.deleteCreatedCredentialDefinition(ctx, resource.Name))
		return nil, err
	}
	return s.credentialResourceToView(ctx, resource)
}

func classifyCredentialCreateError(err error, credentialID string) error {
	if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
		return domainerror.NewAlreadyExists("platformk8s: credential %q already exists", credentialID)
	}
	return err
}

func (s *CredentialManagementService) deleteCreatedCredentialDefinition(ctx context.Context, credentialID string) error {
	if err := s.store.Delete(context.WithoutCancel(ctx), credentialID); err != nil {
		return fmt.Errorf("platformk8s/credentials: rollback credential definition %q: %w", credentialID, err)
	}
	return nil
}
