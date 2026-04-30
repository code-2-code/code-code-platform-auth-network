package outboundhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientFactory builds provider-facing HTTP clients. Envoy owns routing and
// policy enforcement through the transparent egress path.
type ClientFactory struct {
	protocolMode HTTPProtocolMode
	proxyURL     *url.URL
}

type HTTPProtocolMode string

const (
	HTTPProtocolModeHTTP1Only      HTTPProtocolMode = "http1"
	HTTPProtocolModeHTTP2Preferred HTTPProtocolMode = "http2-preferred"
	HTTPProtocolModeHTTP2Required  HTTPProtocolMode = "http2-required"
)

func NewClientFactory() ClientFactory {
	return ClientFactory{protocolMode: HTTPProtocolModeHTTP2Preferred}
}

func NewClientFactoryWithProtocolMode(protocolMode HTTPProtocolMode) ClientFactory {
	return ClientFactory{protocolMode: normalizeHTTPProtocolMode(protocolMode)}
}

func NewClientFactoryWithProxyURL(proxyURL string) (ClientFactory, error) {
	return NewClientFactoryWithOptions(HTTPProtocolModeHTTP2Preferred, proxyURL)
}

func NewClientFactoryWithOptions(protocolMode HTTPProtocolMode, proxyURL string) (ClientFactory, error) {
	parsedProxyURL, err := parseExplicitProxyURL(proxyURL)
	if err != nil {
		return ClientFactory{}, err
	}
	return ClientFactory{
		protocolMode: normalizeHTTPProtocolMode(protocolMode),
		proxyURL:     parsedProxyURL,
	}, nil
}

func (f ClientFactory) NewClient(context.Context) (*http.Client, error) {
	return newClientWithProxyURL(f.protocolMode, f.proxyURL), nil
}

func NewClient() *http.Client {
	return NewClientWithProtocolMode(HTTPProtocolModeHTTP2Preferred)
}

func NewClientWithProtocolMode(protocolMode HTTPProtocolMode) *http.Client {
	return newClientWithProxyURL(protocolMode, nil)
}

func NewClientWithProtocolModeAndProxyURL(protocolMode HTTPProtocolMode, proxyURL string) (*http.Client, error) {
	parsedProxyURL, err := parseExplicitProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}
	return newClientWithProxyURL(protocolMode, parsedProxyURL), nil
}

func newClientWithProxyURL(protocolMode HTTPProtocolMode, proxyURL *url.URL) *http.Client {
	protocolMode = normalizeHTTPProtocolMode(protocolMode)
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	switch protocolMode {
	case HTTPProtocolModeHTTP1Only:
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	case HTTPProtocolModeHTTP2Required:
		transport.ForceAttemptHTTP2 = true
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}
		return &http.Client{
			Transport: requireHTTP2Transport{next: transport},
		}
	default:
		transport.ForceAttemptHTTP2 = true
	}
	return &http.Client{
		Transport: transport,
	}
}

func parseExplicitProxyURL(value string) (*url.URL, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("outbound HTTP proxy URL is invalid: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5" {
		return nil, fmt.Errorf("outbound HTTP proxy URL scheme %q is unsupported", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("outbound HTTP proxy URL host is empty")
	}
	return parsed, nil
}

func normalizeHTTPProtocolMode(protocolMode HTTPProtocolMode) HTTPProtocolMode {
	switch protocolMode {
	case HTTPProtocolModeHTTP1Only, HTTPProtocolModeHTTP2Required:
		return protocolMode
	default:
		return HTTPProtocolModeHTTP2Preferred
	}
}

type requireHTTP2Transport struct {
	next http.RoundTripper
}

func (t requireHTTP2Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.ProtoMajor == 2 {
		return response, nil
	}
	_ = response.Body.Close()
	return nil, fmt.Errorf("outbound HTTP/2 required for %s, got %s", request.URL.Host, response.Proto)
}

// SetBearerAuthorization sets the Authorization header to "Bearer <token>"
// if the token is non-empty after trimming whitespace.
func SetBearerAuthorization(headers http.Header, token string) {
	if token = strings.TrimSpace(token); token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
}
