package credentials

import "time"

const (
	antigravityTokenURL     = "https://oauth2.googleapis.com/token"
	antigravityClientID     = "GOOGLE_OAUTH_CLIENT_ID_PLACEHOLDER.apps.googleusercontent.com"
	antigravityClientSecret = "GOOGLE_OAUTH_CLIENT_SECRET_PLACEHOLDER"
	antigravityRefreshLead  = 5 * time.Minute
)

type AntigravityOAuthRefresherConfig = GoogleOAuthRefresherConfig

type AntigravityOAuthRefresher struct {
	*GoogleOAuthRefresher
}

func init() {
	registerOAuthTokenRefresherFactory("antigravity", func() OAuthTokenRefresher {
		return NewAntigravityOAuthRefresher(AntigravityOAuthRefresherConfig{})
	})
}

func NewAntigravityOAuthRefresher(config AntigravityOAuthRefresherConfig) *AntigravityOAuthRefresher {
	refresher, err := NewGoogleOAuthRefresher(GoogleOAuthRefresherConfig{
		CliID:        "antigravity",
		TokenURL:     valueOrDefault(config.TokenURL, antigravityTokenURL),
		ClientID:     valueOrDefault(config.ClientID, antigravityClientID),
		ClientSecret: valueOrDefault(config.ClientSecret, antigravityClientSecret),
		RefreshLead:  durationOrDefault(config.RefreshLead, antigravityRefreshLead),
		NonRetryableMarkers: []string{
			"invalid_grant",
			"invalid_client",
			"unauthorized_client",
		},
	})
	if err != nil {
		panic(err)
	}
	return &AntigravityOAuthRefresher{GoogleOAuthRefresher: refresher}
}
