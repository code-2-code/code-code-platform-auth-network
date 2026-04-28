package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	credentialcontract "code-code.internal/platform-contract/credential"
)

type googleOAuthUserInfoResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (a *GoogleOAuthAuthorizer) userInfo(ctx context.Context, httpClient *http.Client, accessToken string) (*googleOAuthUserInfoResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: create google userinfo request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: execute google userinfo request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: read google userinfo response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("platformk8s: google userinfo request failed: %s", googleOAuthError(response.StatusCode, body))
	}
	userInfo := &googleOAuthUserInfoResponse{}
	if err := json.Unmarshal(body, userInfo); err != nil {
		return nil, fmt.Errorf("platformk8s: decode google userinfo response: %w", err)
	}
	return userInfo, nil
}

func oauthArtifactFromGoogleTokenResponse(now time.Time, token *googleOAuthTokenResponse, rawResponse string, userInfo *googleOAuthUserInfoResponse) (*credentialcontract.OAuthArtifact, error) {
	if token == nil {
		return nil, fmt.Errorf("platformk8s: google oauth token response is nil")
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
	if userInfo != nil {
		artifact.AccountID = strings.TrimSpace(userInfo.ID)
		artifact.AccountEmail = strings.TrimSpace(userInfo.Email)
	}
	if err := credentialcontract.ValidateOAuthArtifact(artifact); err != nil {
		return nil, err
	}
	return artifact, nil
}
