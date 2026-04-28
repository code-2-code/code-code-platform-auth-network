package authservice

import (
	"context"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	"code-code.internal/platform-k8s/internal/authservice/credentials"
)

type apiKeyCredentialRequest interface {
	GetCredentialId() string
	GetDisplayName() string
	GetPurpose() string
	GetVendorId() string
	GetApiKey() string
}

func (s *Server) CreateAPIKeyCredential(ctx context.Context, request *authv1.CreateAPIKeyCredentialRequest) (*authv1.CreateAPIKeyCredentialResponse, error) {
	view, err := s.writeAPIKeyCredential(ctx, request, true)
	if err != nil {
		return nil, err
	}
	return &authv1.CreateAPIKeyCredentialResponse{Credential: view}, nil
}

func (s *Server) UpdateAPIKeyCredential(ctx context.Context, request *authv1.UpdateAPIKeyCredentialRequest) (*authv1.UpdateAPIKeyCredentialResponse, error) {
	view, err := s.writeAPIKeyCredential(ctx, request, false)
	if err != nil {
		return nil, err
	}
	return &authv1.UpdateAPIKeyCredentialResponse{Credential: view}, nil
}

func (s *Server) writeAPIKeyCredential(ctx context.Context, request apiKeyCredentialRequest, create bool) (*managementv1.CredentialView, error) {
	credential, err := credentials.NewCredential(&credentialv1.CredentialDefinition{
		CredentialId: request.GetCredentialId(),
		DisplayName:  request.GetDisplayName(),
		Purpose:      purposeValue(request.GetPurpose()),
		VendorId:     request.GetVendorId(),
		Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY,
	}, &credentialv1.ResolvedCredential{
		CredentialId: request.GetCredentialId(),
		Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY,
		Material: &credentialv1.ResolvedCredential_ApiKey{
			ApiKey: &credentialv1.ApiKeyCredential{ApiKey: request.GetApiKey()},
		},
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return s.writeCredential(ctx, request.GetCredentialId(), credential, create)
}
