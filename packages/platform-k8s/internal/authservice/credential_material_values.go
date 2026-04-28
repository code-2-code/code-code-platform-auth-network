package authservice

import (
	"context"
	"strings"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) MergeCredentialMaterialValues(
	ctx context.Context,
	request *authv1.MergeCredentialMaterialValuesRequest,
) (*authv1.MergeCredentialMaterialValuesResponse, error) {
	if err := s.credentialWriter.MergeMaterialValues(ctx, request.GetCredentialId(), request.GetValues()); err != nil {
		return nil, grpcError(err)
	}
	return &authv1.MergeCredentialMaterialValuesResponse{Status: "merged"}, nil
}

func (s *Server) ReadCredentialMaterialFields(
	ctx context.Context,
	request *authv1.ReadCredentialMaterialFieldsRequest,
) (*authv1.ReadCredentialMaterialFieldsResponse, error) {
	if s.materialReadPolicy == nil {
		return nil, status.Error(codes.Unavailable, "credential material read policy authorizer is unavailable")
	}
	fields, err := s.materialReadPolicy.AuthorizeCredentialMaterialRead(ctx, request.GetPolicyRef(), request.GetFieldIds())
	if err != nil {
		return nil, err
	}
	values, err := s.credentialWriter.ReadMaterialValues(ctx, request.GetCredentialId())
	if err != nil {
		return nil, grpcError(err)
	}
	out := map[string]string{}
	for _, field := range fields {
		if value := strings.TrimSpace(values[field]); value != "" {
			out[field] = value
		}
	}
	return &authv1.ReadCredentialMaterialFieldsResponse{Values: out}, nil
}
