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

type GoogleOAuthRefresherConfig struct {
	CliID               string
	TokenURL            string
	ClientID            string
	ClientSecret        string
	RefreshLead         time.Duration
	NonRetryableMarkers []string
}

type GoogleOAuthRefresher struct {
	cliID               string
	tokenURL            string
	clientID            string
	clientSecret        string
	refreshLead         time.Duration
	nonRetryableMarkers []string
}

func NewGoogleOAuthRefresher(config GoogleOAuthRefresherConfig) (*GoogleOAuthRefresher, error) {
	if strings.TrimSpace(config.CliID) == "" {
		return nil, fmt.Errorf("credentials: google oauth cli id is empty")
	}
	if strings.TrimSpace(config.TokenURL) == "" || strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" {
		return nil, fmt.Errorf("credentials: google oauth refresher config is incomplete")
	}
	if config.RefreshLead <= 0 {
		config.RefreshLead = 5 * time.Minute
	}
	return &GoogleOAuthRefresher{
		cliID:               strings.TrimSpace(config.CliID),
		tokenURL:            strings.TrimSpace(config.TokenURL),
		clientID:            strings.TrimSpace(config.ClientID),
		clientSecret:        strings.TrimSpace(config.ClientSecret),
		refreshLead:         config.RefreshLead,
		nonRetryableMarkers: append([]string(nil), config.NonRetryableMarkers...),
	}, nil
}

func (r *GoogleOAuthRefresher) CliID() string { return r.cliID }

func (r *GoogleOAuthRefresher) RefreshLead() time.Duration { return r.refreshLead }

func (r *GoogleOAuthRefresher) IsNonRetryable(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	for _, marker := range r.nonRetryableMarkers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func (r *GoogleOAuthRefresher) Refresh(ctx context.Context, httpClient *http.Client, refreshToken string) (*OAuthRefreshResult, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("credentials: %s refresh token is empty", r.cliID)
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {r.clientID},
		"client_secret": {r.clientSecret},
		"refresh_token": {refreshToken},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("credentials: create %s refresh request: %w", r.cliID, err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("credentials: %s refresh request: %w", r.cliID, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("credentials: read %s refresh response: %w", r.cliID, err)
	}
	if response.StatusCode != http.StatusOK {
		var oauthErr struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return nil, fmt.Errorf("credentials: %s refresh failed: %s - %s", r.cliID, oauthErr.Error, oauthErr.ErrorDescription)
		}
		return nil, fmt.Errorf("credentials: %s refresh failed (status %d): %s", r.cliID, response.StatusCode, strings.TrimSpace(string(body)))
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
		return nil, fmt.Errorf("credentials: decode %s refresh response: %w", r.cliID, err)
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return nil, fmt.Errorf("credentials: %s refresh response access_token is empty", r.cliID)
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
