package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
)

const (
	defaultCodexAuthorizationURL = "https://auth.openai.com/oauth/authorize"
	defaultCodexTokenURL         = "https://auth.openai.com/oauth/token"
	defaultCodexClientID         = "app_EMoamEEZ73f0CkXaXp7hrann"
	defaultCodexSessionTTL       = 10 * time.Minute
)

type codexTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type codexIDTokenClaims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Auth  struct {
		ChatGPTAccountID string `json:"chatgpt_account_id"`
	} `json:"https://api.openai.com/auth"`
}

// CodexOAuthAuthorizerConfig groups dependencies for the Codex OAuth authorizer.
type CodexOAuthAuthorizerConfig struct {
	SessionStore      *OAuthSessionStore
	HTTPClientFactory oauthHTTPClientFactory
	Now               func() time.Time
	AuthorizationURL  string
	TokenURL          string
	ClientID          string
	SessionTTL        time.Duration
}

// CodexOAuthAuthorizer implements the Codex OAuth authorization flow.
type CodexOAuthAuthorizer struct {
	sessionStore      *OAuthSessionStore
	httpClientFactory oauthHTTPClientFactory
	now               func() time.Time
	authorizationURL  string
	tokenURL          string
	clientID          string
	sessionTTL        time.Duration
}

func init() {
	registerCodeFlowAuthorizerFactory("codex", func(config CodeFlowAuthorizerFactoryConfig) (credentialcontract.OAuthAuthorizer, error) {
		return NewCodexOAuthAuthorizer(CodexOAuthAuthorizerConfig{
			SessionStore:      config.SessionStore,
			HTTPClientFactory: config.HTTPClientFactory,
		})
	})
}

// NewCodexOAuthAuthorizer creates one Codex OAuth authorizer.
func NewCodexOAuthAuthorizer(config CodexOAuthAuthorizerConfig) (*CodexOAuthAuthorizer, error) {
	if config.SessionStore == nil {
		return nil, fmt.Errorf("platformk8s: oauth authorization session store is nil")
	}
	if config.HTTPClientFactory == nil {
		return nil, fmt.Errorf("platformk8s: oauth http client factory is nil")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if strings.TrimSpace(config.AuthorizationURL) == "" {
		config.AuthorizationURL = defaultCodexAuthorizationURL
	}
	if strings.TrimSpace(config.TokenURL) == "" {
		config.TokenURL = defaultCodexTokenURL
	}
	if strings.TrimSpace(config.ClientID) == "" {
		config.ClientID = defaultCodexClientID
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = defaultCodexSessionTTL
	}
	return &CodexOAuthAuthorizer{
		sessionStore:      config.SessionStore,
		httpClientFactory: config.HTTPClientFactory,
		now:               config.Now,
		authorizationURL:  strings.TrimSpace(config.AuthorizationURL),
		tokenURL:          strings.TrimSpace(config.TokenURL),
		clientID:          strings.TrimSpace(config.ClientID),
		sessionTTL:        config.SessionTTL,
	}, nil
}

// StartAuthorizationSession starts one Codex authorization flow.
func (a *CodexOAuthAuthorizer) StartAuthorizationSession(ctx context.Context, request *credentialcontract.OAuthAuthorizationRequest) (*credentialcontract.OAuthAuthorizationSession, error) {
	if err := credentialcontract.ValidateOAuthAuthorizationRequest(request); err != nil {
		return nil, err
	}
	if request.CliID != "codex" {
		return nil, fmt.Errorf("platformk8s: unsupported oauth cli %q", request.CliID)
	}
	if a == nil || a.sessionStore == nil || a.httpClientFactory == nil {
		return nil, fmt.Errorf("platformk8s: codex oauth authorizer is not initialized")
	}

	sessionID, err := randomHex(12)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: generate oauth session id: %w", err)
	}
	state, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: generate oauth state: %w", err)
	}
	codeVerifier, err := newOAuthCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("platformk8s: generate oauth code verifier: %w", err)
	}
	now := a.now().UTC()
	record := &CodeOAuthSession{
		CliID:               string(request.CliID),
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
		CliID:            "codex",
		SessionID:        record.SessionID,
		AuthorizationURL: authURL,
		ExpiresAt:        record.ExpiresAt,
	}
	if err := credentialcontract.ValidateOAuthAuthorizationSession(session); err != nil {
		return nil, err
	}
	return session, nil
}

// CompleteAuthorizationSession exchanges one authorization code for one OAuth artifact.
func (a *CodexOAuthAuthorizer) CompleteAuthorizationSession(ctx context.Context, exchange *credentialcontract.OAuthAuthorizationExchange) (*credentialcontract.OAuthArtifact, error) {
	if err := credentialcontract.ValidateOAuthAuthorizationExchange(exchange); err != nil {
		return nil, err
	}
	if exchange.CliID != "codex" {
		return nil, fmt.Errorf("platformk8s: unsupported oauth cli %q", exchange.CliID)
	}
	if a == nil || a.sessionStore == nil || a.httpClientFactory == nil {
		return nil, fmt.Errorf("platformk8s: codex oauth authorizer is not initialized")
	}

	record, err := a.sessionStore.GetCodeSession(ctx, string(exchange.CliID), exchange.SessionID)
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

	tokenResponse, rawResponse, err := a.exchangeCodeForTokens(ctx, strings.TrimSpace(exchange.Code), record)
	if err != nil {
		return nil, err
	}
	artifact, err := oauthArtifactFromCodexTokenResponse(a.now().UTC(), tokenResponse, rawResponse)
	if err != nil {
		return nil, err
	}
	return artifact, nil
}

func (a *CodexOAuthAuthorizer) authorizationURLFor(record *CodeOAuthSession) (string, error) {
	if err := validateCodeOAuthSession(record); err != nil {
		return "", err
	}
	values := url.Values{
		"client_id":                  {a.clientID},
		"response_type":              {"code"},
		"redirect_uri":               {record.ProviderRedirectURI},
		"scope":                      {"openid email profile offline_access"},
		"state":                      {record.State},
		"code_challenge":             {oauthCodeChallengeS256(record.CodeVerifier)},
		"code_challenge_method":      {"S256"},
		"prompt":                     {"login"},
		"id_token_add_organizations": {"true"},
		"codex_cli_simplified_flow":  {"true"},
	}
	return a.authorizationURL + "?" + values.Encode(), nil
}

func (a *CodexOAuthAuthorizer) exchangeCodeForTokens(ctx context.Context, code string, record *CodeOAuthSession) (*codexTokenResponse, string, error) {
	httpClient, err := a.httpClientFactory.NewClient(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("platformk8s: resolve codex oauth http client: %w", err)
	}
	values := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {a.clientID},
		"code":          {code},
		"redirect_uri":  {record.ProviderRedirectURI},
		"code_verifier": {record.CodeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.tokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, "", fmt.Errorf("platformk8s: create codex oauth token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("platformk8s: exchange codex oauth token request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("platformk8s: read codex oauth token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("platformk8s: codex oauth token exchange failed with status %d", resp.StatusCode)
	}

	token := &codexTokenResponse{}
	if err := json.Unmarshal(body, token); err != nil {
		return nil, "", fmt.Errorf("platformk8s: decode codex oauth token response: %w", err)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return nil, "", fmt.Errorf("platformk8s: codex oauth token response access token is empty")
	}
	return token, strings.TrimSpace(string(body)), nil
}

func oauthArtifactFromCodexTokenResponse(now time.Time, token *codexTokenResponse, rawResponse string) (*credentialcontract.OAuthArtifact, error) {
	if token == nil {
		return nil, fmt.Errorf("platformk8s: codex oauth token response is nil")
	}
	artifact := &credentialcontract.OAuthArtifact{
		AccessToken:       strings.TrimSpace(token.AccessToken),
		RefreshToken:      strings.TrimSpace(token.RefreshToken),
		IDToken:           strings.TrimSpace(token.IDToken),
		TokenResponseJSON: strings.TrimSpace(rawResponse),
		TokenType:         strings.TrimSpace(token.TokenType),
		Scopes:            oauthScopeList(token.Scope),
	}
	if token.ExpiresIn > 0 {
		expiresAt := now.UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
		artifact.ExpiresAt = &expiresAt
	}
	if artifact.IDToken != "" {
		claims, err := parseCodexIDTokenClaims(artifact.IDToken)
		if err != nil {
			return nil, err
		}
		artifact.AccountEmail = strings.TrimSpace(claims.Email)
		artifact.AccountID = strings.TrimSpace(claims.Auth.ChatGPTAccountID)
		if artifact.AccountID == "" {
			artifact.AccountID = strings.TrimSpace(claims.Sub)
		}
	}
	if err := credentialcontract.ValidateOAuthArtifact(artifact); err != nil {
		return nil, err
	}
	return artifact, nil
}

func parseCodexIDTokenClaims(idToken string) (*codexIDTokenClaims, error) {
	parts := strings.Split(strings.TrimSpace(idToken), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("platformk8s: invalid codex id token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("platformk8s: decode codex id token payload: %w", err)
	}
	claims := &codexIDTokenClaims{}
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, fmt.Errorf("platformk8s: decode codex id token claims: %w", err)
	}
	return claims, nil
}
