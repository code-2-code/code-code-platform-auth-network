package credentials

import (
	"context"
	"strings"

	"code-code.internal/go-contract/domainerror"
)

// MergeMaterialValues updates explicit credential material keys without changing
// the credential definition or kind-specific material model.
func (s *CredentialManagementService) MergeMaterialValues(ctx context.Context, credentialID string, values map[string]string) error {
	if s == nil {
		return domainerror.NewValidation("platformk8s: credential service is nil")
	}
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return domainerror.NewValidation("platformk8s: credential id is empty")
	}
	updates := trimMaterialValueUpdates(values)
	if len(updates) == 0 {
		return nil
	}
	if _, err := s.ReadDefinition(ctx, credentialID); err != nil {
		return err
	}
	return s.materialStore.MergeValues(ctx, credentialID, updates)
}

func trimMaterialValueUpdates(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
