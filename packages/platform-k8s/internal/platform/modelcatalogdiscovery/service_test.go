package modelcatalogdiscovery

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	modelcatalogdiscoveryv1 "code-code.internal/go-contract/model_catalog_discovery/v1"
	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
)

func TestServiceProbeUsesPathQueryAndHeaders(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodGet; got != want {
			t.Fatalf("method = %q, want %q", got, want)
		}
		if got, want := r.URL.Path, "/api/codex/models"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		if got, want := r.URL.Query().Get("client_version"), "0.98.0"; got != want {
			t.Fatalf("client_version = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("User-Agent"), outboundhttp.DefaultProviderUserAgent; got != want {
			t.Fatalf("user-agent = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Authorization"), "Bearer token"; got != want {
			t.Fatalf("authorization = %q, want %q", got, want)
		}
		_, _ = w.Write([]byte(`{"models":[{"slug":"gpt-5.4"}]}`))
	}))
	defer upstream.Close()

	service, err := NewService(httpClientFactoryFunc(func(context.Context) (*http.Client, error) {
		return upstream.Client(), nil
	}))
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	modelIDs, err := fetchModelIDs(context.Background(), service, Request{
		BaseURL: upstream.URL + "/api/codex",
		Headers: http.Header{"Authorization": []string{"Bearer token"}},
		Operation: &modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation{
			Path: "models",
			QueryParameters: []*modelcatalogdiscoveryv1.DiscoveryParameter{{
				Name: "client_version",
				Value: &modelcatalogdiscoveryv1.DiscoveryParameter_DynamicValue{
					DynamicValue: modelcatalogdiscoveryv1.DiscoveryDynamicValue_DISCOVERY_DYNAMIC_VALUE_CLIENT_VERSION,
				},
			}},
			ResponseKind: modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_CODEX_MODELS,
		},
		DynamicValues: DynamicValues{ClientVersion: "0.98.0"},
	})
	if err != nil {
		t.Fatalf("fetchModelIDs() error = %v", err)
	}
	if got, want := len(modelIDs), 1; got != want {
		t.Fatalf("len(modelIDs) = %d, want %d", got, want)
	}
	if got, want := modelIDs[0], "gpt-5.4"; got != want {
		t.Fatalf("modelIDs[0] = %q, want %q", got, want)
	}
}

func TestServiceProbeSkipsMissingDynamicQueryParameter(t *testing.T) {
	t.Parallel()

	var gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"models":[{"slug":"gpt-5.4"}]}`))
	}))
	defer upstream.Close()

	service, err := NewService(httpClientFactoryFunc(func(context.Context) (*http.Client, error) {
		return upstream.Client(), nil
	}))
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	modelIDs, err := fetchModelIDs(context.Background(), service, Request{
		BaseURL: upstream.URL,
		Operation: &modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation{
			Path: "models",
			QueryParameters: []*modelcatalogdiscoveryv1.DiscoveryParameter{{
				Name: "client_version",
				Value: &modelcatalogdiscoveryv1.DiscoveryParameter_DynamicValue{
					DynamicValue: modelcatalogdiscoveryv1.DiscoveryDynamicValue_DISCOVERY_DYNAMIC_VALUE_CLIENT_VERSION,
				},
			}},
			ResponseKind: modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_CODEX_MODELS,
		},
	})
	if err != nil {
		t.Fatalf("fetchModelIDs() error = %v", err)
	}
	if gotQuery != "" {
		t.Fatalf("raw query = %q, want empty", gotQuery)
	}
	if len(modelIDs) != 1 || modelIDs[0] != "gpt-5.4" {
		t.Fatalf("model ids = %#v", modelIDs)
	}
}

func TestServiceProbeSupportsPostJSONBodyAndHeaders(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPost; got != want {
			t.Fatalf("method = %q, want %q", got, want)
		}
		if got, want := r.URL.Path, "/v1internal:fetchAvailableModels"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("User-Agent"), "antigravity/1.11.5"; got != want {
			t.Fatalf("user-agent = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Content-Type"), "application/json"; got != want {
			t.Fatalf("content-type = %q, want %q", got, want)
		}
		body, _ := io.ReadAll(r.Body)
		if got, want := strings.TrimSpace(string(body)), `{"project":"workspacecli-1"}`; got != want {
			t.Fatalf("body = %q, want %q", got, want)
		}
		_, _ = w.Write([]byte(`{"models":{"gemini-2.5-pro":{},"gemini-3-pro-preview":{}}}`))
	}))
	defer upstream.Close()

	service, err := NewService(httpClientFactoryFunc(func(context.Context) (*http.Client, error) {
		return upstream.Client(), nil
	}))
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	modelIDs, err := fetchModelIDs(context.Background(), service, Request{
		BaseURL: upstream.URL,
		Operation: &modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation{
			Path:   "v1internal:fetchAvailableModels",
			Method: modelcatalogdiscoveryv1.DiscoveryHTTPMethod_DISCOVERY_HTTP_METHOD_POST,
			RequestHeaders: []*modelcatalogdiscoveryv1.DiscoveryParameter{{
				Name: "User-Agent",
				Value: &modelcatalogdiscoveryv1.DiscoveryParameter_Literal{
					Literal: "antigravity/1.11.5",
				},
			}},
			JsonBodyFields: []*modelcatalogdiscoveryv1.DiscoveryParameter{{
				Name: "project",
				Value: &modelcatalogdiscoveryv1.DiscoveryParameter_DynamicValue{
					DynamicValue: modelcatalogdiscoveryv1.DiscoveryDynamicValue_DISCOVERY_DYNAMIC_VALUE_PROJECT_ID,
				},
			}},
			ResponseKind: modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_ANTIGRAVITY_MODELS_MAP,
		},
		DynamicValues: DynamicValues{ProjectID: "workspacecli-1"},
	})
	if err != nil {
		t.Fatalf("fetchModelIDs() error = %v", err)
	}
	if len(modelIDs) != 2 {
		t.Fatalf("len(modelIDs) = %d, want 2", len(modelIDs))
	}
}

func fetchModelIDs(ctx context.Context, service *Service, request Request) ([]string, error) {
	response, err := service.Fetch(ctx, request)
	if err != nil {
		return nil, err
	}
	return ParseModelIDs(response.Body, request.Operation.GetResponseKind())
}

type httpClientFactoryFunc func(ctx context.Context) (*http.Client, error)

func (f httpClientFactoryFunc) NewClient(ctx context.Context) (*http.Client, error) {
	return f(ctx)
}
