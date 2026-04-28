package authservice

import (
	"context"
	"fmt"
	"time"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	"code-code.internal/platform-k8s/internal/authservice/credentials"
)

func (s *Server) ImportOAuthCredential(ctx context.Context, request *authv1.ImportOAuthCredentialRequest) (*authv1.ImportOAuthCredentialResponse, error) {
	definition, err := s.oauthImporter.ImportOAuthCredential(ctx, &credentialcontract.OAuthImportRequest{
		CliID:        credentialcontract.OAuthCLIID(request.GetCliId()),
		CredentialID: request.GetCredentialId(),
		DisplayName:  request.GetDisplayName(),
		Artifact:     oauthArtifactFromProto(request.GetArtifact()),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &authv1.ImportOAuthCredentialResponse{Definition: definition}, nil
}

func (s *Server) EnsureFresh(ctx context.Context, request *authv1.EnsureFreshRequest) (*authv1.EnsureFreshResponse, error) {
	result, err := s.refreshRunner.EnsureFresh(ctx, request.GetCredentialId(), credentials.EnsureFreshOptions{
		MinTTL:       time.Duration(request.GetMinTtlSeconds()) * time.Second,
		ForceRefresh: request.GetForceRefresh(),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	response := &authv1.EnsureFreshResponse{}
	if result != nil {
		response.Outcome = result.Outcome
		response.Refreshed = result.Refreshed
		response.ExpiresAt = timeToProto(result.ExpiresAt)
		response.NextRefreshAfter = timeToProto(result.NextRefreshAfter)
		response.LastRefreshedAt = timeToProto(result.LastRefreshedAt)
	}
	return response, nil
}

func (s *Server) RefreshOAuthDue(ctx context.Context, _ *authv1.RefreshOAuthDueRequest) (*authv1.RefreshOAuthDueResponse, error) {
	if s == nil || s.refreshRunner == nil {
		return nil, grpcError(fmt.Errorf("platformk8s/authservice: oauth refresh runner is not initialized"))
	}
	if err := s.refreshRunner.RunAll(ctx); err != nil {
		return nil, grpcError(err)
	}
	return &authv1.RefreshOAuthDueResponse{Status: "completed"}, nil
}

func (s *Server) ScanOAuthSessions(ctx context.Context, _ *authv1.ScanOAuthSessionsRequest) (*authv1.ScanOAuthSessionsResponse, error) {
	if s == nil || s.oauthSessions == nil {
		return nil, grpcError(errOAuthSessionUnavailable())
	}
	if err := s.oauthSessions.ScanSessions(ctx); err != nil {
		return nil, grpcError(err)
	}
	return &authv1.ScanOAuthSessionsResponse{Status: "completed"}, nil
}

func oauthArtifactFromProto(artifact *authv1.OAuthArtifact) credentialcontract.OAuthArtifact {
	if artifact == nil {
		return credentialcontract.OAuthArtifact{}
	}
	out := credentialcontract.OAuthArtifact{
		AccessToken:       artifact.GetAccessToken(),
		RefreshToken:      artifact.GetRefreshToken(),
		IDToken:           artifact.GetIdToken(),
		TokenResponseJSON: artifact.GetTokenResponseJson(),
		TokenType:         artifact.GetTokenType(),
		AccountID:         artifact.GetAccountId(),
		AccountEmail:      artifact.GetAccountEmail(),
		Scopes:            append([]string(nil), artifact.GetScopes()...),
	}
	if artifact.GetExpiresAt() != nil {
		expiresAt := artifact.GetExpiresAt().AsTime().UTC()
		out.ExpiresAt = &expiresAt
	}
	return out
}
