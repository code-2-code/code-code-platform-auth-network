package modelcatalogdiscovery

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"code-code.internal/go-contract/domainerror"
	modelcatalogdiscoveryv1 "code-code.internal/go-contract/model_catalog_discovery/v1"
	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
)

const (
	maxResponseBodyBytes = 2 << 20
	maxErrorBodyBytes    = 1 << 11
)

type HTTPClientFactory interface {
	NewClient(ctx context.Context) (*http.Client, error)
}

type Request struct {
	BaseURL       string
	Headers       http.Header
	Operation     *modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation
	DynamicValues DynamicValues
}

type DynamicValues struct {
	ClientVersion string
	ProjectID     string
}

type Service struct {
	httpClientFactory HTTPClientFactory
}

type Response struct {
	StatusCode int
	Body       []byte
}

func NewService(httpClientFactory HTTPClientFactory) (*Service, error) {
	if httpClientFactory == nil {
		return nil, fmt.Errorf("platformk8s/modelcatalogdiscovery: http client factory is nil")
	}
	return &Service{httpClientFactory: httpClientFactory}, nil
}

func (s *Service) Fetch(ctx context.Context, request Request) (*Response, error) {
	if s == nil || s.httpClientFactory == nil {
		return nil, fmt.Errorf("platformk8s/modelcatalogdiscovery: service is not initialized")
	}
	if request.Operation == nil {
		return nil, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: operation is required")
	}
	baseURL := strings.TrimSpace(request.BaseURL)
	if override := strings.TrimSpace(request.Operation.GetBaseUrl()); override != "" {
		baseURL = override
	}
	if baseURL == "" {
		return nil, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: base_url is required")
	}
	discoveryURL, err := operationURL(baseURL, request.Operation, request.DynamicValues)
	if err != nil {
		return nil, err
	}
	method, err := operationMethod(request.Operation)
	if err != nil {
		return nil, err
	}
	body, hasJSONBody, err := jsonBody(request.Operation, request.DynamicValues)
	if err != nil {
		return nil, err
	}
	headers, err := mergeHeaders(request.Headers, request.Operation, request.DynamicValues)
	if err != nil {
		return nil, err
	}
	httpClient, err := s.httpClientFactory.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, discoveryURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("platformk8s/modelcatalogdiscovery: create operation request: %w", err)
	}
	httpRequest.Header = headers
	if httpRequest.Header.Get("Accept") == "" {
		httpRequest.Header.Set("Accept", "application/json")
	}
	outboundhttp.SetDefaultProviderUserAgent(httpRequest.Header)
	if hasJSONBody && httpRequest.Header.Get("Content-Type") == "" {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	response, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: operation request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBodyBytes))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = strings.ToLower(http.StatusText(response.StatusCode))
		}
		return nil, domainerror.NewValidation(
			"platformk8s/modelcatalogdiscovery: operation failed with status %d: %s",
			response.StatusCode,
			message,
		)
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: read operation response failed: %v", err)
	}
	return &Response{
		StatusCode: response.StatusCode,
		Body:       bodyBytes,
	}, nil
}
