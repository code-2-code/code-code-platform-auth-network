package outboundhttp

import "net/http"

const DefaultProviderUserAgent = "code-code-platform-k8s-provider"

// SetDefaultProviderUserAgent applies the platform default provider-facing
// user agent when the caller did not already choose one.
func SetDefaultProviderUserAgent(headers http.Header) {
	if headers == nil {
		return
	}
	if headers.Get("User-Agent") != "" {
		return
	}
	headers.Set("User-Agent", DefaultProviderUserAgent)
}
