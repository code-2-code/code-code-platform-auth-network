package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var googleOAuthTokenExchangeRetryDelays = []time.Duration{
	200 * time.Millisecond,
	800 * time.Millisecond,
}

type googleOAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type googleOAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type googleOAuthTokenExchangeAttemptError struct {
	err       error
	retryable bool
}

func (e *googleOAuthTokenExchangeAttemptError) Error() string {
	return e.err.Error()
}

func (e *googleOAuthTokenExchangeAttemptError) Unwrap() error {
	return e.err
}

func (a *GoogleOAuthAuthorizer) exchangeCodeForTokens(ctx context.Context, code string, record *CodeOAuthSession) (*googleOAuthTokenResponse, string, *http.Client, error) {
	httpClient, err := a.httpClientFactory.NewClient(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("platformk8s: resolve google oauth http client: %w", err)
	}
	values := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"code":          {code},
		"redirect_uri":  {record.ProviderRedirectURI},
		"code_verifier": {record.CodeVerifier},
	}
	var lastErr error
	for attempt := 0; attempt <= len(googleOAuthTokenExchangeRetryDelays); attempt++ {
		token, rawResponse, err := a.doTokenExchange(ctx, httpClient, values)
		if err == nil {
			return token, rawResponse, httpClient, nil
		}
		lastErr = err
		if !retryableGoogleOAuthTokenExchangeError(err) || attempt == len(googleOAuthTokenExchangeRetryDelays) {
			return nil, "", nil, err
		}
		if err := sleepContext(ctx, googleOAuthTokenExchangeRetryDelays[attempt]); err != nil {
			return nil, "", nil, err
		}
	}
	return nil, "", nil, lastErr
}

func (a *GoogleOAuthAuthorizer) doTokenExchange(ctx context.Context, httpClient *http.Client, values url.Values) (*googleOAuthTokenResponse, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.tokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, "", fmt.Errorf("platformk8s: create google oauth token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, "", retryableGoogleOAuthTokenExchangeAttemptError(
			fmt.Errorf("platformk8s: exchange google oauth token request: %w", err),
		)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, "", fmt.Errorf("platformk8s: read google oauth token response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("platformk8s: google oauth token exchange failed: %s", googleOAuthError(response.StatusCode, body))
		if retryableGoogleOAuthStatus(response.StatusCode) {
			return nil, "", retryableGoogleOAuthTokenExchangeAttemptError(err)
		}
		return nil, "", err
	}
	token := &googleOAuthTokenResponse{}
	if err := json.Unmarshal(body, token); err != nil {
		return nil, "", fmt.Errorf("platformk8s: decode google oauth token response: %w", err)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return nil, "", fmt.Errorf("platformk8s: google oauth token response access token is empty")
	}
	return token, strings.TrimSpace(string(body)), nil
}

func retryableGoogleOAuthTokenExchangeAttemptError(err error) error {
	return &googleOAuthTokenExchangeAttemptError{err: err, retryable: true}
}

func retryableGoogleOAuthTokenExchangeError(err error) bool {
	var attemptErr *googleOAuthTokenExchangeAttemptError
	return errors.As(err, &attemptErr) && attemptErr.retryable
}

func retryableGoogleOAuthStatus(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func googleOAuthError(statusCode int, body []byte) string {
	oauthErr := &googleOAuthErrorResponse{}
	if err := json.Unmarshal(body, oauthErr); err == nil && strings.TrimSpace(oauthErr.Error) != "" {
		description := strings.TrimSpace(oauthErr.ErrorDescription)
		if description == "" {
			return fmt.Sprintf("%s (status %d)", strings.TrimSpace(oauthErr.Error), statusCode)
		}
		return fmt.Sprintf("%s - %s (status %d)", strings.TrimSpace(oauthErr.Error), description, statusCode)
	}
	return fmt.Sprintf("status %d: %s", statusCode, strings.TrimSpace(string(body)))
}
