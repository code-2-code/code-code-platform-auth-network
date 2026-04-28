package authservice

import (
	"context"
	"fmt"
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	"code-code.internal/platform-k8s/internal/authservice/credentials"
)

func (s *Server) ListCredentials(ctx context.Context, _ *authv1.ListCredentialsRequest) (*authv1.ListCredentialsResponse, error) {
	items, err := s.credentialWriter.List(ctx)
	if err != nil {
		return nil, grpcError(err)
	}
	return &authv1.ListCredentialsResponse{Items: items}, nil
}

func (s *Server) RenameCredential(ctx context.Context, request *authv1.RenameCredentialRequest) (*authv1.RenameCredentialResponse, error) {
	if err := s.credentialWriter.UpdateDisplayName(ctx, request.GetCredentialId(), request.GetDisplayName()); err != nil {
		return nil, grpcError(err)
	}
	items, err := s.credentialWriter.List(ctx)
	if err != nil {
		return nil, grpcError(err)
	}
	for _, item := range items {
		if item.GetCredentialId() == request.GetCredentialId() {
			return &authv1.RenameCredentialResponse{Credential: item}, nil
		}
	}
	return nil, grpcError(fmt.Errorf("platformk8s/authservice: credential %q not found after rename", request.GetCredentialId()))
}

func (s *Server) DeleteCredential(ctx context.Context, request *authv1.DeleteCredentialRequest) (*authv1.DeleteCredentialResponse, error) {
	if err := s.credentialWriter.Delete(ctx, request.GetCredentialId(), s.credentialRefChecker); err != nil {
		return nil, grpcError(err)
	}
	return &authv1.DeleteCredentialResponse{Status: "deleted"}, nil
}

func (s *Server) writeCredential(ctx context.Context, credentialID string, credential *credentials.Credential, create bool) (*managementv1.CredentialView, error) {
	if create {
		view, err := s.credentialWriter.Create(ctx, credential)
		if err != nil {
			return nil, grpcError(err)
		}
		return view, nil
	}
	view, err := s.credentialWriter.Update(ctx, credentialID, credential)
	if err != nil {
		return nil, grpcError(err)
	}
	return view, nil
}

func purposeValue(value string) credentialv1.CredentialPurpose {
	if raw, ok := credentialv1.CredentialPurpose_value[strings.TrimSpace(value)]; ok {
		return credentialv1.CredentialPurpose(raw)
	}
	return credentialv1.CredentialPurpose_CREDENTIAL_PURPOSE_UNSPECIFIED
}
