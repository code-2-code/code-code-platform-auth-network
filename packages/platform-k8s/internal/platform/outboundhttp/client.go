package outboundhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// ClientFactory builds provider-facing HTTP clients. Envoy owns routing and
// policy enforcement through the transparent egress path.
type ClientFactory struct {
	protocolMode HTTPProtocolMode
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

func (f ClientFactory) NewClient(context.Context) (*http.Client, error) {
	return NewClientWithProtocolMode(f.protocolMode), nil
}

func NewClient() *http.Client {
	return NewClientWithProtocolMode(HTTPProtocolModeHTTP2Preferred)
}

func NewClientWithProtocolMode(protocolMode HTTPProtocolMode) *http.Client {
	protocolMode = normalizeHTTPProtocolMode(protocolMode)
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
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
