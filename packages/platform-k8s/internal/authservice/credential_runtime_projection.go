package authservice

import (
	"context"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
)

func (s *Server) GetCredentialRuntimeProjection(ctx context.Context, request *authv1.GetCredentialRuntimeProjectionRequest) (*authv1.GetCredentialRuntimeProjectionResponse, error) {
	projection, err := s.credentialWriter.ReadRuntimeProjection(ctx, request.GetCredentialId())
	if err != nil {
		return nil, err
	}
	return &authv1.GetCredentialRuntimeProjectionResponse{
		Credential: &authv1.CredentialRuntimeProjection{
			CredentialId:   projection.CredentialID,
			CredentialKind: projection.Kind,
			VendorId:       projection.VendorID,
			CliId:          projection.CLIID,
		},
	}, nil
}
