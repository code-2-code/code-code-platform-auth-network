package credentials

import "time"

const (
	geminiTokenURL     = "https://oauth2.googleapis.com/token"
	geminiClientID     = "GOOGLE_OAUTH_CLIENT_ID_PLACEHOLDER.apps.googleusercontent.com"
	geminiClientSecret = "GOOGLE_OAUTH_CLIENT_SECRET_PLACEHOLDER"
	geminiRefreshLead  = 5 * time.Minute
)

type GeminiOAuthRefresherConfig = GoogleOAuthRefresherConfig

type GeminiOAuthRefresher struct {
	*GoogleOAuthRefresher
}

func init() {
	registerOAuthTokenRefresherFactory("gemini-cli", func() OAuthTokenRefresher {
		return NewGeminiOAuthRefresher(GeminiOAuthRefresherConfig{})
	})
}

func NewGeminiOAuthRefresher(config GeminiOAuthRefresherConfig) *GeminiOAuthRefresher {
	refresher, err := NewGoogleOAuthRefresher(GoogleOAuthRefresherConfig{
		CliID:        "gemini-cli",
		TokenURL:     valueOrDefault(config.TokenURL, geminiTokenURL),
		ClientID:     valueOrDefault(config.ClientID, geminiClientID),
		ClientSecret: valueOrDefault(config.ClientSecret, geminiClientSecret),
		RefreshLead:  durationOrDefault(config.RefreshLead, geminiRefreshLead),
		NonRetryableMarkers: []string{
			"invalid_grant",
			"invalid_client",
			"unauthorized_client",
		},
	})
	if err != nil {
		panic(err)
	}
	return &GeminiOAuthRefresher{GoogleOAuthRefresher: refresher}
}
