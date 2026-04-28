package authservice

import (
	"context"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	"code-code.internal/platform-k8s/internal/authservice/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type oauthCredentialRequest interface {
	GetCredentialId() string
	GetDisplayName() string
	GetPurpose() string
	GetVendorId() string
	GetCliId() string
	GetAccessToken() string
	GetRefreshToken() string
	GetIdToken() string
	GetTokenType() string
	GetAccountId() string
	GetScopes() []string
	GetExpiresAt() *timestamppb.Timestamp
}

func (s *Server) CreateOAuthCredential(ctx context.Context, request *authv1.CreateOAuthCredentialRequest) (*authv1.CreateOAuthCredentialResponse, error) {
	view, err := s.writeOAuthCredential(ctx, request, true)
	if err != nil {
		return nil, err
	}
	return &authv1.CreateOAuthCredentialResponse{Credential: view}, nil
}

func (s *Server) UpdateOAuthCredential(ctx context.Context, request *authv1.UpdateOAuthCredentialRequest) (*authv1.UpdateOAuthCredentialResponse, error) {
	view, err := s.writeOAuthCredential(ctx, request, false)
	if err != nil {
		return nil, err
	}
	return &authv1.UpdateOAuthCredentialResponse{Credential: view}, nil
}

func (s *Server) writeOAuthCredential(ctx context.Context, request oauthCredentialRequest, create bool) (*managementv1.CredentialView, error) {
	credential, err := credentials.NewCredential(&credentialv1.CredentialDefinition{
		CredentialId: request.GetCredentialId(),
		DisplayName:  request.GetDisplayName(),
		Purpose:      purposeValue(request.GetPurpose()),
		VendorId:     request.GetVendorId(),
		Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
		KindMetadata: &credentialv1.CredentialDefinition_OauthMetadata{
			OauthMetadata: &credentialv1.OAuthMetadata{CliId: request.GetCliId()},
		},
	}, &credentialv1.ResolvedCredential{
		CredentialId: request.GetCredentialId(),
		Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
		Material: &credentialv1.ResolvedCredential_Oauth{
			Oauth: &credentialv1.OAuthCredential{
				AccessToken:  request.GetAccessToken(),
				RefreshToken: request.GetRefreshToken(),
				IdToken:      request.GetIdToken(),
				TokenType:    request.GetTokenType(),
				AccountId:    request.GetAccountId(),
				Scopes:       append([]string(nil), request.GetScopes()...),
				ExpiresAt:    request.GetExpiresAt(),
			},
		},
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return s.writeCredential(ctx, request.GetCredentialId(), credential, create)
}
