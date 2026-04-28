package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	codexTokenURL    = "https://auth.openai.com/oauth/token"
	codexClientID    = "app_EMoamEEZ73f0CkXaXp7hrann"
	codexRefreshLead = 5 * time.Minute
)

// CodexOAuthRefresher implements OAuthTokenRefresher for Codex (OpenAI).
type CodexOAuthRefresher struct {
	tokenURL string
	clientID string
}

// CodexOAuthRefresherConfig groups optional overrides for the Codex refresher.
type CodexOAuthRefresherConfig struct {
	TokenURL string
	ClientID string
}

func init() {
	registerOAuthTokenRefresherFactory("codex", func() OAuthTokenRefresher {
		return NewCodexOAuthRefresher(CodexOAuthRefresherConfig{})
	})
}

// NewCodexOAuthRefresher creates one Codex OAuth token refresher.
func NewCodexOAuthRefresher(config CodexOAuthRefresherConfig) *CodexOAuthRefresher {
	tokenURL := strings.TrimSpace(config.TokenURL)
	if tokenURL == "" {
		tokenURL = codexTokenURL
	}
	clientID := strings.TrimSpace(config.ClientID)
	if clientID == "" {
		clientID = codexClientID
	}
	return &CodexOAuthRefresher{
		tokenURL: tokenURL,
		clientID: clientID,
	}
}

func (r *CodexOAuthRefresher) CliID() string { return "codex" }

func (r *CodexOAuthRefresher) RefreshLead() time.Duration { return codexRefreshLead }

func (r *CodexOAuthRefresher) IsNonRetryable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "refresh_token_reused") ||
		strings.Contains(msg, "invalid_grant") ||
		strings.Contains(msg, "unauthorized_client")
}

func (r *CodexOAuthRefresher) Refresh(ctx context.Context, httpClient *http.Client, refreshToken string) (*OAuthRefreshResult, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("credentials: codex refresh token is empty")
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {r.clientID},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("credentials: create codex refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("credentials: codex refresh request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("credentials: read codex refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("credentials: codex refresh failed (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("credentials: decode codex refresh response: %w", err)
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return nil, fmt.Errorf("credentials: codex refresh response access_token is empty")
	}

	result := &OAuthRefreshResult{
		AccessToken:       strings.TrimSpace(tokenResp.AccessToken),
		RefreshToken:      strings.TrimSpace(tokenResp.RefreshToken),
		IDToken:           strings.TrimSpace(tokenResp.IDToken),
		TokenResponseJSON: strings.TrimSpace(string(body)),
		TokenType:         strings.TrimSpace(tokenResp.TokenType),
	}
	if tokenResp.ExpiresIn > 0 {
		expiresAt := time.Now().UTC().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		result.ExpiresAt = &expiresAt
	}
	if tokenResp.Scope != "" {
		result.Scopes = trimNonEmpty(strings.Fields(tokenResp.Scope))
	}
	return result, nil
}
