package oauth

import (
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
)

const (
	defaultGeminiAuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	defaultGeminiTokenURL         = "https://oauth2.googleapis.com/token"
	defaultGeminiUserInfoURL      = "https://www.googleapis.com/oauth2/v2/userinfo"
	defaultGeminiClientID         = "GOOGLE_OAUTH_CLIENT_ID_PLACEHOLDER.apps.googleusercontent.com"
	defaultGeminiClientSecret     = "GOOGLE_OAUTH_CLIENT_SECRET_PLACEHOLDER"
	defaultGeminiSessionTTL       = 10 * time.Minute
	geminiCLIID                   = "gemini-cli"
)

var defaultGeminiScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
}

type GeminiOAuthAuthorizerConfig = GoogleOAuthAuthorizerConfig

type GeminiOAuthAuthorizer struct {
	*GoogleOAuthAuthorizer
}

func init() {
	registerCodeFlowAuthorizerFactory(geminiCLIID, func(config CodeFlowAuthorizerFactoryConfig) (credentialcontract.OAuthAuthorizer, error) {
		return NewGeminiOAuthAuthorizer(GeminiOAuthAuthorizerConfig{
			SessionStore:      config.SessionStore,
			HTTPClientFactory: config.HTTPClientFactory,
		})
	})
}

func NewGeminiOAuthAuthorizer(config GeminiOAuthAuthorizerConfig) (*GeminiOAuthAuthorizer, error) {
	authorizer, err := NewGoogleOAuthAuthorizer(GoogleOAuthAuthorizerConfig{
		CliID:             geminiCLIID,
		SessionStore:      config.SessionStore,
		HTTPClientFactory: config.HTTPClientFactory,
		Now:               config.Now,
		AuthorizationURL:  valueOrDefault(config.AuthorizationURL, defaultGeminiAuthorizationURL),
		TokenURL:          valueOrDefault(config.TokenURL, defaultGeminiTokenURL),
		UserInfoURL:       valueOrDefault(config.UserInfoURL, defaultGeminiUserInfoURL),
		ClientID:          valueOrDefault(config.ClientID, defaultGeminiClientID),
		ClientSecret:      valueOrDefault(config.ClientSecret, defaultGeminiClientSecret),
		Scopes:            slicesOrDefault(config.Scopes, defaultGeminiScopes),
		SessionTTL:        durationOrDefault(config.SessionTTL, defaultGeminiSessionTTL),
	})
	if err != nil {
		return nil, err
	}
	return &GeminiOAuthAuthorizer{GoogleOAuthAuthorizer: authorizer}, nil
}
