package credentials

import (
	"context"
	"net/http"
	"time"
)

// OAuthRefreshResult holds the outcome of one token refresh attempt.
type OAuthRefreshResult struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	// TokenResponseJSON stores the raw OAuth token response body when later
	// projection needs stable token-response fields.
	TokenResponseJSON string
	TokenType         string
	ExpiresAt         *time.Time
	AccountEmail      string
	AccountID         string
	Scopes            []string
}

// OAuthTokenRefresher refreshes one OAuth credential using its refresh token.
// Each supported CLI OAuth surface implements this interface.
type OAuthTokenRefresher interface {
	// CliID returns the lowercase cli_id (e.g. "codex", "qwen-cli").
	CliID() string

	// Refresh exchanges a refresh token for new access+refresh tokens.
	// The caller supplies an HTTP client that respects platform network policy;
	// implementations must use it for all outbound requests.
	// Returns a non-nil error for all failures. Callers determine retry
	// eligibility via IsNonRetryable.
	Refresh(ctx context.Context, httpClient *http.Client, refreshToken string) (*OAuthRefreshResult, error)

	// RefreshLead returns how far in advance of expiration this CLI's
	// tokens should be refreshed. CLIs with short-lived tokens should
	// return a larger lead (e.g. 5 minutes for typical 1-hour tokens).
	RefreshLead() time.Duration

	// IsNonRetryable returns true if the error indicates that retrying
	// will not help (e.g. refresh_token_reused, invalid_grant).
	IsNonRetryable(err error) bool
}
