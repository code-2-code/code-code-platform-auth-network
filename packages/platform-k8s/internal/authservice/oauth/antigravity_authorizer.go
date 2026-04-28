package oauth

import (
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
)

const (
	defaultAntigravityAuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	defaultAntigravityTokenURL         = "https://oauth2.googleapis.com/token"
	defaultAntigravityUserInfoURL      = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json"
	defaultAntigravityClientID         = "GOOGLE_OAUTH_CLIENT_ID_PLACEHOLDER.apps.googleusercontent.com"
	defaultAntigravityClientSecret     = "GOOGLE_OAUTH_CLIENT_SECRET_PLACEHOLDER"
	defaultAntigravitySessionTTL       = 10 * time.Minute
	antigravityCLIID                   = "antigravity"
)

var defaultAntigravityScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
	"https://www.googleapis.com/auth/cclog",
	"https://www.googleapis.com/auth/experimentsandconfigs",
}

type AntigravityOAuthAuthorizerConfig = GoogleOAuthAuthorizerConfig

type AntigravityOAuthAuthorizer struct {
	*GoogleOAuthAuthorizer
}

func init() {
	registerCodeFlowAuthorizerFactory(antigravityCLIID, func(config CodeFlowAuthorizerFactoryConfig) (credentialcontract.OAuthAuthorizer, error) {
		return NewAntigravityOAuthAuthorizer(AntigravityOAuthAuthorizerConfig{
			SessionStore:      config.SessionStore,
			HTTPClientFactory: config.HTTPClientFactory,
		})
	})
}

func NewAntigravityOAuthAuthorizer(config AntigravityOAuthAuthorizerConfig) (*AntigravityOAuthAuthorizer, error) {
	authorizer, err := NewGoogleOAuthAuthorizer(GoogleOAuthAuthorizerConfig{
		CliID:             antigravityCLIID,
		SessionStore:      config.SessionStore,
		HTTPClientFactory: config.HTTPClientFactory,
		Now:               config.Now,
		AuthorizationURL:  valueOrDefault(config.AuthorizationURL, defaultAntigravityAuthorizationURL),
		TokenURL:          valueOrDefault(config.TokenURL, defaultAntigravityTokenURL),
		UserInfoURL:       valueOrDefault(config.UserInfoURL, defaultAntigravityUserInfoURL),
		ClientID:          valueOrDefault(config.ClientID, defaultAntigravityClientID),
		ClientSecret:      valueOrDefault(config.ClientSecret, defaultAntigravityClientSecret),
		Scopes:            slicesOrDefault(config.Scopes, defaultAntigravityScopes),
		SessionTTL:        durationOrDefault(config.SessionTTL, defaultAntigravitySessionTTL),
	})
	if err != nil {
		return nil, err
	}
	return &AntigravityOAuthAuthorizer{GoogleOAuthAuthorizer: authorizer}, nil
}
