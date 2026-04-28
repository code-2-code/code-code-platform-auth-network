package credentials

import (
	"context"
	"fmt"
	"strings"

	credentialcontract "code-code.internal/platform-contract/credential"
)

func (s *CredentialManagementService) ReadOAuthArtifact(ctx context.Context, credentialID string) (*credentialcontract.OAuthArtifact, error) {
	if s == nil {
		return nil, fmt.Errorf("platformk8s: credential service is nil")
	}
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return nil, fmt.Errorf("platformk8s: credential id is empty")
	}
	values, err := s.materialStore.ReadValues(ctx, credentialID)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: read oauth credential material %q: %w", credentialID, err)
	}
	artifact, err := OAuthArtifactFromValues(values)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: read oauth artifact %q: %w", credentialID, err)
	}
	return artifact, nil
}

func (s *CredentialManagementService) ReadMaterialValue(ctx context.Context, credentialID, materialKey string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("platformk8s: credential service is nil")
	}
	credentialID = strings.TrimSpace(credentialID)
	materialKey = strings.TrimSpace(materialKey)
	if credentialID == "" {
		return "", fmt.Errorf("platformk8s: credential id is empty")
	}
	if materialKey == "" {
		return "", fmt.Errorf("platformk8s: material key is empty")
	}
	values, err := s.materialStore.ReadValues(ctx, credentialID)
	if err != nil {
		return "", fmt.Errorf("platformk8s: read credential material %q: %w", credentialID, err)
	}
	return getOptionalValue(values, materialKey), nil
}

func (s *CredentialManagementService) ReadMaterialValues(ctx context.Context, credentialID string) (map[string]string, error) {
	if s == nil {
		return nil, fmt.Errorf("platformk8s: credential service is nil")
	}
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return nil, fmt.Errorf("platformk8s: credential id is empty")
	}
	return s.materialStore.ReadValues(ctx, credentialID)
}
