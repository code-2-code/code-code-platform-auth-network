package outboundhttp

import (
	"net/http"
	"testing"
)

func TestNewClientUsesHTTP2PreferredTransparentEgressTransport(t *testing.T) {
	t.Parallel()

	client := NewClient()

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("outbound client should not honor HTTP proxy environment variables")
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("transparent egress client should attempt HTTP/2 when the upstream path supports it")
	}
	if transport.TLSNextProto != nil {
		t.Fatal("HTTP/2 preferred client should not disable ALPN handlers")
	}
}

func TestHTTP1OnlyClientDisablesHTTP2(t *testing.T) {
	t.Parallel()

	client := NewClientWithProtocolMode(HTTPProtocolModeHTTP1Only)

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("HTTP/1-only client should not attempt HTTP/2")
	}
	if transport.TLSNextProto == nil {
		t.Fatal("HTTP/1-only client should disable HTTP/2 ALPN handlers")
	}
}

func TestHTTP2RequiredClientWrapsTransport(t *testing.T) {
	t.Parallel()

	client := NewClientWithProtocolMode(HTTPProtocolModeHTTP2Required)

	transport, ok := client.Transport.(requireHTTP2Transport)
	if !ok {
		t.Fatalf("transport type = %T, want requireHTTP2Transport", client.Transport)
	}
	base, ok := transport.next.(*http.Transport)
	if !ok {
		t.Fatalf("wrapped transport type = %T, want *http.Transport", transport.next)
	}
	if !base.ForceAttemptHTTP2 {
		t.Fatal("HTTP/2-required client should attempt HTTP/2")
	}
	if got := base.TLSClientConfig.GetConfigForClient; got != nil {
		t.Fatal("HTTP/2-required client should keep static TLS config")
	}
	if got := base.TLSClientConfig.NextProtos; len(got) != 1 || got[0] != "h2" {
		t.Fatalf("NextProtos = %v, want [h2]", got)
	}
}
