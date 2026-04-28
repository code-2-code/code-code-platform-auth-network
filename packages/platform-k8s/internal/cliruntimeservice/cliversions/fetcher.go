package cliversions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
)

const maxResponseBytes = 1 << 20

type HTTPClientFactory interface {
	NewClient(ctx context.Context) (*http.Client, error)
}

type Fetcher struct {
	clientFactory   HTTPClientFactory
	npmBaseURL      string
	homebrewBaseURL string
}

func NewFetcher(client *http.Client) *Fetcher {
	return NewFetcherWithHTTPClientFactory(staticHTTPClientFactory{client: client})
}

func NewFetcherWithHTTPClientFactory(factory HTTPClientFactory) *Fetcher {
	if factory == nil {
		factory = staticHTTPClientFactory{}
	}
	return &Fetcher{
		clientFactory:   factory,
		npmBaseURL:      "https://registry.npmjs.org",
		homebrewBaseURL: "https://formulae.brew.sh/api/cask",
	}
}

type staticHTTPClientFactory struct {
	client *http.Client
}

func (f staticHTTPClientFactory) NewClient(context.Context) (*http.Client, error) {
	if f.client != nil {
		return f.client, nil
	}
	return &http.Client{Timeout: 10 * time.Second}, nil
}

func (f *Fetcher) Fetch(ctx context.Context, source Source) (string, error) {
	switch source.Kind {
	case SourceKindNPMRegistry:
		return f.fetchNPMDistTag(ctx, source)
	case SourceKindHomebrewCask:
		return f.fetchHomebrewCask(ctx, source)
	default:
		return "", fmt.Errorf("platformk8s/cliversions: unsupported source kind %q", source.Kind)
	}
}

func (f *Fetcher) fetchNPMDistTag(ctx context.Context, source Source) (string, error) {
	endpoint := strings.TrimRight(f.npmBaseURL, "/") + "/-/package/" + url.PathEscape(source.PackageName) + "/dist-tags"
	payload, err := f.getJSON(ctx, endpoint)
	if err != nil {
		return "", err
	}
	tags := map[string]string{}
	if err := json.Unmarshal(payload, &tags); err != nil {
		return "", fmt.Errorf("platformk8s/cliversions: decode npm dist-tags for %q: %w", source.PackageName, err)
	}
	version := strings.TrimSpace(tags[source.DistTag])
	if version == "" {
		return "", fmt.Errorf("platformk8s/cliversions: npm dist-tag %q missing for %q", source.DistTag, source.PackageName)
	}
	return version, nil
}

func (f *Fetcher) fetchHomebrewCask(ctx context.Context, source Source) (string, error) {
	endpoint := strings.TrimRight(f.homebrewBaseURL, "/") + "/" + url.PathEscape(source.Cask) + ".json"
	payload, err := f.getJSON(ctx, endpoint)
	if err != nil {
		return "", err
	}
	response := struct {
		Version string `json:"version"`
	}{}
	if err := json.Unmarshal(payload, &response); err != nil {
		return "", fmt.Errorf("platformk8s/cliversions: decode homebrew cask %q: %w", source.Cask, err)
	}
	version := strings.TrimSpace(strings.SplitN(response.Version, ",", 2)[0])
	if version == "" {
		return "", fmt.Errorf("platformk8s/cliversions: homebrew cask %q version is empty", source.Cask)
	}
	return version, nil
}

func (f *Fetcher) getJSON(ctx context.Context, endpoint string) ([]byte, error) {
	if f == nil || f.clientFactory == nil {
		return nil, fmt.Errorf("platformk8s/cliversions: http client factory is not initialized")
	}
	client, err := f.clientFactory.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/cliversions: create client for %q: %w", endpoint, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/cliversions: create request %q: %w", endpoint, err)
	}
	request.Header.Set("Accept", "application/json")
	outboundhttp.SetDefaultProviderUserAgent(request.Header)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/cliversions: fetch %q: %w", endpoint, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("platformk8s/cliversions: read %q: %w", endpoint, err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("platformk8s/cliversions: fetch %q failed with status %d", endpoint, response.StatusCode)
	}
	return body, nil
}
