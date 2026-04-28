package cliversions

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
)

func TestFetcherFetchNPMDistTag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/-/package/@openai/codex/dist-tags"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		_, _ = w.Write([]byte(`{"latest":"0.121.0","alpha":"0.122.0-alpha.10"}`))
	}))
	defer server.Close()

	fetcher := NewFetcher(server.Client())
	fetcher.npmBaseURL = server.URL
	version, err := fetcher.Fetch(context.Background(), Source{
		Kind:        SourceKindNPMRegistry,
		PackageName: "@openai/codex",
		DistTag:     "latest",
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if got, want := version, "0.121.0"; got != want {
		t.Fatalf("version = %q, want %q", got, want)
	}
}

func TestFetcherFetchHomebrewCask(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/antigravity.json"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		_, _ = w.Write([]byte(`{"version":"1.22.2,5206900187463680"}`))
	}))
	defer server.Close()

	fetcher := NewFetcher(server.Client())
	fetcher.homebrewBaseURL = server.URL
	version, err := fetcher.Fetch(context.Background(), Source{
		Kind: SourceKindHomebrewCask,
		Cask: "antigravity",
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if got, want := version, "1.22.2"; got != want {
		t.Fatalf("version = %q, want %q", got, want)
	}
}

func TestFetcherUsesConfiguredClientFactory(t *testing.T) {
	factory := &recordingHTTPClientFactory{
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
				Header:     make(http.Header),
			}, nil
		})},
	}
	fetcher := NewFetcherWithHTTPClientFactory(factory)
	fetcher.npmBaseURL = "https://registry.npmjs.org"

	_, err := fetcher.getJSON(context.Background(), "https://registry.npmjs.org/-/package/test/dist-tags")
	if err != nil {
		t.Fatalf("getJSON() error = %v", err)
	}
	if !factory.called {
		t.Fatal("NewClient() was not called")
	}
}

func TestFetcherSetsDefaultUserAgent(t *testing.T) {
	factory := &recordingHTTPClientFactory{
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if got, want := request.Header.Get("User-Agent"), outboundhttp.DefaultProviderUserAgent; got != want {
				t.Fatalf("user-agent = %q, want %q", got, want)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"latest":"0.121.0"}`)),
				Header:     make(http.Header),
			}, nil
		})},
	}
	fetcher := NewFetcherWithHTTPClientFactory(factory)
	fetcher.npmBaseURL = "https://registry.npmjs.org"

	if _, err := fetcher.Fetch(context.Background(), Source{
		Kind:        SourceKindNPMRegistry,
		PackageName: "@openai/codex",
		DistTag:     "latest",
	}); err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
}

type recordingHTTPClientFactory struct {
	client *http.Client
	called bool
}

func (f *recordingHTTPClientFactory) NewClient(context.Context) (*http.Client, error) {
	f.called = true
	return f.client, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
