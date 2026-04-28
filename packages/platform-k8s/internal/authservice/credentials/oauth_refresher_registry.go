package credentials

import (
	"sort"
	"strings"
)

type oauthTokenRefresherFactory func() OAuthTokenRefresher

var oauthTokenRefresherFactories = map[string]oauthTokenRefresherFactory{}

func registerOAuthTokenRefresherFactory(cliID string, factory oauthTokenRefresherFactory) {
	trimmedCLIID := strings.TrimSpace(cliID)
	if trimmedCLIID == "" || factory == nil {
		return
	}
	oauthTokenRefresherFactories[trimmedCLIID] = factory
}

func DefaultOAuthTokenRefreshers() []OAuthTokenRefresher {
	cliIDs := make([]string, 0, len(oauthTokenRefresherFactories))
	for cliID := range oauthTokenRefresherFactories {
		cliIDs = append(cliIDs, cliID)
	}
	sort.Strings(cliIDs)
	refreshers := make([]OAuthTokenRefresher, 0, len(cliIDs))
	for _, cliID := range cliIDs {
		factory := oauthTokenRefresherFactories[cliID]
		if factory == nil {
			continue
		}
		if refresher := factory(); refresher != nil {
			refreshers = append(refreshers, refresher)
		}
	}
	return refreshers
}
