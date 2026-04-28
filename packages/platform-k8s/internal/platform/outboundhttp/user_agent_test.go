package outboundhttp

import (
	"net/http"
	"testing"
)

func TestSetDefaultProviderUserAgent(t *testing.T) {
	t.Parallel()

	headers := http.Header{}
	SetDefaultProviderUserAgent(headers)

	if got, want := headers.Get("User-Agent"), DefaultProviderUserAgent; got != want {
		t.Fatalf("user-agent = %q, want %q", got, want)
	}
}

func TestSetDefaultProviderUserAgentPreservesExplicitValue(t *testing.T) {
	t.Parallel()

	headers := http.Header{"User-Agent": []string{"vendor-specific-client"}}
	SetDefaultProviderUserAgent(headers)

	if got, want := headers.Get("User-Agent"), "vendor-specific-client"; got != want {
		t.Fatalf("user-agent = %q, want %q", got, want)
	}
}
