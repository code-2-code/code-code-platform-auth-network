package authservice

import (
	"context"
	"fmt"
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	oauthv1 "code-code.internal/go-contract/platform/oauth/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	"code-code.internal/platform-k8s/internal/authservice/oauth"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type OAuthSessionConfig struct {
	Client                ctrlclient.Client
	APIReader             ctrlclient.Reader
	Namespace             string
	ResourceStore         oauth.AuthorizationSessionResourceStore
	HostedCallbackBaseURL string
	OAuthImporter         credentialcontract.OAuthCredentialImporter
	Observer              oauth.SessionObserver
}

type OAuthSessionServer struct {
	oauthv1.UnimplementedOAuthSessionServiceServer

	runtime *oauthSessionRuntime
}

func NewOAuthSessionServer(config OAuthSessionConfig) (*OAuthSessionServer, error) {
	if config.Client == nil {
		return nil, fmt.Errorf("platformk8s/authservice: oauth session client is nil")
	}
	if config.APIReader == nil {
		return nil, fmt.Errorf("platformk8s/authservice: oauth session api reader is nil")
	}
	if strings.TrimSpace(config.Namespace) == "" {
		return nil, fmt.Errorf("platformk8s/authservice: oauth session namespace is empty")
	}
	if config.OAuthImporter == nil {
		return nil, fmt.Errorf("platformk8s/authservice: oauth session importer is nil")
	}
	runtime, err := assembleOAuthSessionRuntime(config.Client, config.APIReader, config.Namespace, config.ResourceStore, config.HostedCallbackBaseURL, config.OAuthImporter, config.Observer)
	if err != nil {
		return nil, err
	}
	return &OAuthSessionServer{runtime: runtime}, nil
}

func (s *OAuthSessionServer) SessionManager() *oauth.SessionManager {
	if s == nil || s.runtime == nil {
		return nil
	}
	return s.runtime.sessionManager
}

func (s *OAuthSessionServer) ScanSessions(ctx context.Context) error {
	if s == nil || s.runtime == nil || s.runtime.sessionReconciler == nil {
		return errOAuthSessionUnavailable()
	}
	return s.runtime.sessionReconciler.ScanSessions(ctx)
}

func (s *OAuthSessionServer) StartOAuthAuthorizationSession(ctx context.Context, request *oauthv1.StartOAuthAuthorizationSessionRequest) (*oauthv1.StartOAuthAuthorizationSessionResponse, error) {
	if s == nil || s.runtime == nil || s.runtime.sessionManager == nil {
		return nil, grpcError(fmt.Errorf("platformk8s/authservice: oauth session manager is not initialized"))
	}
	session, err := s.runtime.sessionManager.StartSession(ctx, &credentialv1.OAuthAuthorizationSessionSpec{
		CliId:              strings.TrimSpace(request.GetCliId()),
		Flow:               request.GetFlow(),
		TargetCredentialId: strings.TrimSpace(request.GetTargetCredentialId()),
		TargetDisplayName:  strings.TrimSpace(request.GetTargetDisplayName()),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &oauthv1.StartOAuthAuthorizationSessionResponse{Session: session}, nil
}

func (s *OAuthSessionServer) GetOAuthAuthorizationSession(ctx context.Context, request *oauthv1.GetOAuthAuthorizationSessionRequest) (*oauthv1.GetOAuthAuthorizationSessionResponse, error) {
	if s == nil || s.runtime == nil || s.runtime.sessionManager == nil {
		return nil, grpcError(fmt.Errorf("platformk8s/authservice: oauth session manager is not initialized"))
	}
	session, err := s.runtime.sessionManager.GetSession(ctx, strings.TrimSpace(request.GetSessionId()))
	if err != nil {
		return nil, grpcError(err)
	}
	return &oauthv1.GetOAuthAuthorizationSessionResponse{Session: session}, nil
}

func (s *OAuthSessionServer) CancelOAuthAuthorizationSession(ctx context.Context, request *oauthv1.CancelOAuthAuthorizationSessionRequest) (*oauthv1.CancelOAuthAuthorizationSessionResponse, error) {
	if s == nil || s.runtime == nil || s.runtime.sessionManager == nil {
		return nil, grpcError(fmt.Errorf("platformk8s/authservice: oauth session manager is not initialized"))
	}
	session, err := s.runtime.sessionManager.CancelSession(ctx, strings.TrimSpace(request.GetSessionId()))
	if err != nil {
		return nil, grpcError(err)
	}
	return &oauthv1.CancelOAuthAuthorizationSessionResponse{Session: session}, nil
}
