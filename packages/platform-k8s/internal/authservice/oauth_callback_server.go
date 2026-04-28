package authservice

import (
	"context"
	"fmt"
	"strings"
	"time"

	oauthv1 "code-code.internal/go-contract/platform/oauth/v1"
	"code-code.internal/platform-k8s/internal/authservice/oauth"
)

// OAuthCallbackServer implements platform.oauth.v1 callback recording.
type OAuthCallbackServer struct {
	oauthv1.UnimplementedOAuthCallbackServiceServer

	sessions *oauth.SessionManager
	now      func() time.Time
}

// NewOAuthCallbackServer creates one callback recording gRPC server.
func NewOAuthCallbackServer(sessions *oauth.SessionManager) (*OAuthCallbackServer, error) {
	if sessions == nil {
		return nil, fmt.Errorf("platformk8s/authservice: oauth callback session manager is nil")
	}
	return &OAuthCallbackServer{
		sessions: sessions,
		now:      time.Now,
	}, nil
}

// RecordOAuthCodeCallback records one provider callback into the pending session secret.
func (s *OAuthCallbackServer) RecordOAuthCodeCallback(ctx context.Context, request *oauthv1.RecordOAuthCodeCallbackRequest) (*oauthv1.RecordOAuthCodeCallbackResponse, error) {
	if s == nil || s.sessions == nil {
		return nil, grpcError(fmt.Errorf("platformk8s/authservice: oauth callback server is not initialized"))
	}
	event, err := s.sessions.RecordCodeCallback(ctx, strings.TrimSpace(request.GetProviderId()), &oauth.OAuthCodeCallbackPayload{
		Code:                strings.TrimSpace(request.GetCode()),
		State:               strings.TrimSpace(request.GetState()),
		ProviderRedirectURI: strings.TrimSpace(request.GetProviderRedirectUri()),
		Error:               strings.TrimSpace(request.GetError()),
		ErrorDescription:    strings.TrimSpace(request.GetErrorDescription()),
		ReceivedAt:          s.now().UTC(),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &oauthv1.RecordOAuthCodeCallbackResponse{SessionId: event.SessionID}, nil
}
