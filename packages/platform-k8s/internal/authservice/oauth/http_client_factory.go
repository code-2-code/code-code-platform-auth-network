package oauth

import (
	"context"
	"net/http"
)

type oauthHTTPClientFactory interface {
	NewClient(ctx context.Context) (*http.Client, error)
}
