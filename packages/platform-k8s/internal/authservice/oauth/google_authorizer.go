package oauth

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
)

type GoogleOAuthAuthorizerConfig struct {
	CliID             credentialcontract.OAuthCLIID
	SessionStore      *OAuthSessionStore
	HTTPClientFactory oauthHTTPClientFactory
	Now               func() time.Time
	AuthorizationURL  string
	TokenURL          string
	UserInfoURL       string
	ClientID          string
	ClientSecret      string
	Scopes            []string
	SessionTTL        time.Duration
}

type GoogleOAuthAuthorizer struct {
	cliID             credentialcontract.OAuthCLIID
	sessionStore      *OAuthSessionStore
	httpClientFactory oauthHTTPClientFactory
	now               func() time.Time
	authorizationURL  string
	tokenURL          string
	userInfoURL       string
	clientID          string
	clientSecret      string
	scopes            []string
	sessionTTL        time.Duration
}

func NewGoogleOAuthAuthorizer(config GoogleOAuthAuthorizerConfig) (*GoogleOAuthAuthorizer, error) {
	if config.SessionStore == nil {
		return nil, fmt.Errorf("platformk8s: google oauth session store is nil")
	}
	if config.HTTPClientFactory == nil {
		return nil, fmt.Errorf("platformk8s: google oauth http client factory is nil")
	}
	if strings.TrimSpace(string(config.CliID)) == "" {
		return nil, fmt.Errorf("platformk8s: google oauth cli id is empty")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = 10 * time.Minute
	}
	if strings.TrimSpace(config.AuthorizationURL) == "" || strings.TrimSpace(config.TokenURL) == "" || strings.TrimSpace(config.UserInfoURL) == "" {
		return nil, fmt.Errorf("platformk8s: google oauth endpoints are incomplete")
	}
	if strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" {
		return nil, fmt.Errorf("platformk8s: google oauth client is incomplete")
	}
	return &GoogleOAuthAuthorizer{
		cliID:             credentialcontract.OAuthCLIID(strings.TrimSpace(string(config.CliID))),
		sessionStore:      config.SessionStore,
		httpClientFactory: config.HTTPClientFactory,
		now:               config.Now,
		authorizationURL:  strings.TrimSpace(config.AuthorizationURL),
		tokenURL:          strings.TrimSpace(config.TokenURL),
		userInfoURL:       strings.TrimSpace(config.UserInfoURL),
		clientID:          strings.TrimSpace(config.ClientID),
		clientSecret:      strings.TrimSpace(config.ClientSecret),
		scopes:            trimNonEmptyStrings(config.Scopes),
		sessionTTL:        config.SessionTTL,
	}, nil
}

func (a *GoogleOAuthAuthorizer) StartAuthorizationSession(ctx context.Context, request *credentialcontract.OAuthAuthorizationRequest) (*credentialcontract.OAuthAuthorizationSession, error) {
	if err := credentialcontract.ValidateOAuthAuthorizationRequest(request); err != nil {
		return nil, err
	}
	if request.CliID != a.cliID {
		return nil, fmt.Errorf("platformk8s: unsupported oauth cli %q", request.CliID)
	}
	sessionID, err := randomHex(12)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: generate google oauth session id: %w", err)
	}
	state, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: generate google oauth state: %w", err)
	}
	codeVerifier, err := newOAuthCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("platformk8s: generate google oauth code verifier: %w", err)
	}
	now := a.now().UTC()
	record := &CodeOAuthSession{
		CliID:               string(a.cliID),
		SessionID:           sessionID,
		ProviderRedirectURI: strings.TrimSpace(request.ProviderRedirectURI),
		State:               state,
		CodeVerifier:        codeVerifier,
		ExpiresAt:           now.Add(a.sessionTTL),
	}
	if err := a.sessionStore.PutCodeSession(ctx, record); err != nil {
		return nil, err
	}
	authURL, err := a.authorizationURLFor(record)
	if err != nil {
		return nil, err
	}
	session := &credentialcontract.OAuthAuthorizationSession{
		CliID:            a.cliID,
		SessionID:        record.SessionID,
		AuthorizationURL: authURL,
		ExpiresAt:        record.ExpiresAt,
	}
	if err := credentialcontract.ValidateOAuthAuthorizationSession(session); err != nil {
		return nil, err
	}
	return session, nil
}

func (a *GoogleOAuthAuthorizer) CompleteAuthorizationSession(ctx context.Context, exchange *credentialcontract.OAuthAuthorizationExchange) (*credentialcontract.OAuthArtifact, error) {
	if err := credentialcontract.ValidateOAuthAuthorizationExchange(exchange); err != nil {
		return nil, err
	}
	if exchange.CliID != a.cliID {
		return nil, fmt.Errorf("platformk8s: unsupported oauth cli %q", exchange.CliID)
	}
	record, err := a.sessionStore.GetCodeSession(ctx, string(a.cliID), exchange.SessionID)
	if err != nil {
		return nil, err
	}
	if a.now().UTC().After(record.ExpiresAt.UTC()) {
		return nil, fmt.Errorf("platformk8s: oauth authorization session %q expired", exchange.SessionID)
	}
	if strings.TrimSpace(exchange.State) != record.State {
		return nil, fmt.Errorf("platformk8s: oauth authorization session %q state mismatch", exchange.SessionID)
	}
	if strings.TrimSpace(exchange.ProviderRedirectURI) != record.ProviderRedirectURI {
		return nil, fmt.Errorf("platformk8s: oauth authorization session %q provider redirect uri mismatch", exchange.SessionID)
	}
	token, rawResponse, httpClient, err := a.exchangeCodeForTokens(ctx, strings.TrimSpace(exchange.Code), record)
	if err != nil {
		return nil, err
	}
	userInfo, err := a.userInfo(ctx, httpClient, strings.TrimSpace(token.AccessToken))
	if err != nil {
		return nil, err
	}
	return oauthArtifactFromGoogleTokenResponse(a.now().UTC(), token, rawResponse, userInfo)
}

func (a *GoogleOAuthAuthorizer) authorizationURLFor(record *CodeOAuthSession) (string, error) {
	if err := validateCodeOAuthSession(record); err != nil {
		return "", err
	}
	values := url.Values{
		"client_id":             {a.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {record.ProviderRedirectURI},
		"scope":                 {strings.Join(a.scopes, " ")},
		"state":                 {record.State},
		"access_type":           {"offline"},
		"prompt":                {"consent"},
		"code_challenge":        {oauthCodeChallengeS256(record.CodeVerifier)},
		"code_challenge_method": {"S256"},
	}
	return a.authorizationURL + "?" + values.Encode(), nil
}
