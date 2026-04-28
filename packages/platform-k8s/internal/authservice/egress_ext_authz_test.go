package authservice

import (
	"context"
	"testing"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	providerv1 "code-code.internal/go-contract/provider/v1"
	"code-code.internal/platform-k8s/internal/egressauth"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyauthv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
)

func TestEgressExtAuthzCheckInjectsRuntimeRequestHeader(t *testing.T) {
	runtimeContext := &fakeRuntimeContextClient{
		response: &managementv1.ResolveAgentRunRuntimeContextResponse{
			Metadata: &managementv1.AgentRunRuntimeMetadata{
				CredentialId:       "cred-1",
				TargetHosts:        []string{"api.example.test"},
				TargetPathPrefixes: []string{"/v1"},
				RequestHeaderNames: []string{"authorization"},
				HeaderValuePrefix:  "Bearer",
			},
		},
	}
	server := &Server{
		agentSessions: runtimeContext,
		credentialResolver: &fakeCredentialResolver{
			credential: &credentialv1.ResolvedCredential{
				GrantId: "cred-1",
				Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
				Material: &credentialv1.ResolvedCredential_Session{
					Session: &credentialv1.SessionCredential{Values: map[string]string{
						"authorization": "synthetic-token",
					}},
				},
			},
		},
	}

	response, err := NewEgressExtAuthzServer(server).Check(context.Background(), extAuthzCheckRequest("10.0.0.12", "api.example.test:443", "/v1/chat/completions"))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := codes.Code(response.GetStatus().GetCode()), codes.OK; got != want {
		t.Fatalf("status code = %v, want %v", got, want)
	}
	if got, want := runtimeContext.request.GetPod().GetIp(), "10.0.0.12"; got != want {
		t.Fatalf("runtime source pod.ip = %q, want %q", got, want)
	}
	headers := response.GetOkResponse().GetHeaders()
	if len(headers) != 1 {
		t.Fatalf("headers len = %d, want 1", len(headers))
	}
	if got, want := headers[0].GetHeader().GetKey(), "authorization"; got != want {
		t.Fatalf("header key = %q, want %q", got, want)
	}
	if got, want := headers[0].GetHeader().GetValue(), "Bearer synthetic-token"; got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
}

func TestEgressExtAuthzCheckInjectsProviderSurfaceRequestHeader(t *testing.T) {
	resolver := &fakeCredentialResolver{
		credential: &credentialv1.ResolvedCredential{
			GrantId: "cred-1",
			Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
			Material: &credentialv1.ResolvedCredential_Oauth{
				Oauth: &credentialv1.OAuthCredential{AccessToken: "surface-token", TokenType: "Bearer"},
			},
		},
	}
	server := &Server{
		namespace:          "code-code",
		providers:          fakeProviderStore{providers: []*providerv1.Provider{providerWithSurface("provider-1", "surface-1", "cred-1", "https://api.example.test/v1")}},
		credentialResolver: resolver,
	}

	response, err := NewEgressExtAuthzServer(server).Check(context.Background(), extAuthzCheckRequestWithPrincipalAndHeaders(
		"10.0.0.12",
		"spiffe://cluster.local/ns/code-code/sa/platform-provider-service",
		"api.example.test:443",
		"/v1/models",
		map[string]string{
			egressauth.HeaderProviderSurfaceBindingID: "surface-1",
			egressauth.HeaderRequestHeaderNames:       "authorization",
			egressauth.HeaderHeaderValuePrefix:        "Bearer",
			egressauth.HeaderRequestHeaderRulesJSON:   `[{"mode":"bearer","headerName":"authorization"}]`,
			"authorization":                           "Bearer stale-client-token",
		},
	))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := codes.Code(response.GetStatus().GetCode()), codes.OK; got != want {
		t.Fatalf("status code = %v, want %v", got, want)
	}
	if got, want := resolver.grantID, "cred-1"; got != want {
		t.Fatalf("resolved credential id = %q, want %q", got, want)
	}
	headers := response.GetOkResponse().GetHeaders()
	if len(headers) != 1 {
		t.Fatalf("headers len = %d, want 1", len(headers))
	}
	if got, want := headers[0].GetHeader().GetKey(), "authorization"; got != want {
		t.Fatalf("header key = %q, want %q", got, want)
	}
	if got, want := headers[0].GetHeader().GetValue(), "Bearer surface-token"; got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
	if !containsHeaderName(response.GetOkResponse().GetHeadersToRemove(), egressauth.HeaderProviderSurfaceBindingID) {
		t.Fatalf("headers_to_remove = %v, want %s", response.GetOkResponse().GetHeadersToRemove(), egressauth.HeaderProviderSurfaceBindingID)
	}
}

func TestEgressExtAuthzCheckUsesSourcePrincipalNamespace(t *testing.T) {
	runtimeContext := &fakeRuntimeContextClient{
		response: &managementv1.ResolveAgentRunRuntimeContextResponse{
			Metadata: &managementv1.AgentRunRuntimeMetadata{
				CredentialId:       "cred-1",
				TargetHosts:        []string{"api.example.test"},
				TargetPathPrefixes: []string{"/v1"},
				RequestHeaderNames: []string{"authorization"},
			},
		},
	}
	server := &Server{
		agentSessions: runtimeContext,
		credentialResolver: &fakeCredentialResolver{
			credential: &credentialv1.ResolvedCredential{
				GrantId: "cred-1",
				Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
				Material: &credentialv1.ResolvedCredential_Session{
					Session: &credentialv1.SessionCredential{Values: map[string]string{
						"authorization": "synthetic-token",
					}},
				},
			},
		},
	}

	response, err := NewEgressExtAuthzServer(server).Check(context.Background(), extAuthzCheckRequestWithPrincipal("10.0.0.12", "spiffe://cluster.local/ns/code-code-runs/sa/agent-runtime", "api.example.test:443", "/v1/chat/completions"))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := codes.Code(response.GetStatus().GetCode()), codes.OK; got != want {
		t.Fatalf("status code = %v, want %v", got, want)
	}
	pod := runtimeContext.request.GetPod()
	if got, want := pod.GetNamespace(), "code-code-runs"; got != want {
		t.Fatalf("runtime source pod.namespace = %q, want %q", got, want)
	}
	if got, want := pod.GetIp(), "10.0.0.12"; got != want {
		t.Fatalf("runtime source pod.ip = %q, want %q", got, want)
	}
}

func TestEgressExtAuthzCheckSkipsRuntimeLookupOutsideRuntimeNamespace(t *testing.T) {
	runtimeContext := &fakeRuntimeContextClient{
		response: &managementv1.ResolveAgentRunRuntimeContextResponse{
			Metadata: &managementv1.AgentRunRuntimeMetadata{
				CredentialId:       "cred-1",
				TargetHosts:        []string{"api.example.test"},
				TargetPathPrefixes: []string{"/v1"},
				RequestHeaderNames: []string{"authorization"},
			},
		},
	}
	server := &Server{
		runtimeNamespace:      "code-code-runs",
		agentSessions:         runtimeContext,
		credentialResolver:    &fakeCredentialResolver{},
		headerRewritePolicies: nil,
	}

	response, err := NewEgressExtAuthzServer(server).Check(context.Background(), extAuthzCheckRequestWithPrincipal(
		"10.0.0.12",
		"spiffe://cluster.local/ns/code-code/sa/l7-smoke-client",
		"api.example.test:443",
		"/v1/chat/completions",
	))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := codes.Code(response.GetStatus().GetCode()), codes.OK; got != want {
		t.Fatalf("status code = %v, want %v", got, want)
	}
	if runtimeContext.request != nil {
		t.Fatalf("runtime context request = %v, want nil", runtimeContext.request)
	}
	if len(response.GetOkResponse().GetHeaders()) != 0 {
		t.Fatalf("headers = %v, want empty", response.GetOkResponse().GetHeaders())
	}
}

func TestExtAuthzPeerNamespace(t *testing.T) {
	for _, test := range []struct {
		name      string
		principal string
		want      string
	}{
		{
			name:      "spiffe",
			principal: "spiffe://cluster.local/ns/code-code-runs/sa/agent-runtime",
			want:      "code-code-runs",
		},
		{
			name:      "empty",
			principal: "",
			want:      "",
		},
		{
			name:      "malformed",
			principal: "agent-runtime",
			want:      "",
		},
		{
			name:      "non-spiffe",
			principal: "https://issuer.example/ns/code-code-runs/sa/agent-runtime",
			want:      "",
		},
		{
			name:      "missing-service-account",
			principal: "spiffe://cluster.local/ns/code-code-runs",
			want:      "",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := extAuthzPeerNamespace(test.principal); got != test.want {
				t.Fatalf("extAuthzPeerNamespace() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestEgressExtAuthzCheckAllowsWhenRuntimeSourceMissing(t *testing.T) {
	response, err := NewEgressExtAuthzServer(&Server{}).Check(context.Background(), extAuthzCheckRequest("", "api.example.test:443", "/v1/chat/completions"))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := codes.Code(response.GetStatus().GetCode()), codes.OK; got != want {
		t.Fatalf("status code = %v, want %v", got, want)
	}
	if len(response.GetOkResponse().GetHeaders()) != 0 {
		t.Fatalf("headers = %v, want empty", response.GetOkResponse().GetHeaders())
	}
}

func TestEgressExtAuthzCheckAllowsSkippedTargetMismatch(t *testing.T) {
	runtimeContext := &fakeRuntimeContextClient{
		response: &managementv1.ResolveAgentRunRuntimeContextResponse{
			Metadata: &managementv1.AgentRunRuntimeMetadata{
				CredentialId:       "cred-1",
				TargetHosts:        []string{"api.example.test"},
				TargetPathPrefixes: []string{"/v1"},
				RequestHeaderNames: []string{"authorization"},
				HeaderValuePrefix:  "Bearer",
			},
		},
	}
	server := &Server{agentSessions: runtimeContext}

	response, err := NewEgressExtAuthzServer(server).Check(context.Background(), extAuthzCheckRequest("10.0.0.12", "other.example.test:443", "/v1/chat/completions"))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := codes.Code(response.GetStatus().GetCode()), codes.OK; got != want {
		t.Fatalf("status code = %v, want %v", got, want)
	}
	if len(response.GetOkResponse().GetHeaders()) != 0 {
		t.Fatalf("headers = %v, want empty", response.GetOkResponse().GetHeaders())
	}
}

func TestEgressExtAuthzCheckDeniesResolverFailure(t *testing.T) {
	runtimeContext := &fakeRuntimeContextClient{
		response: &managementv1.ResolveAgentRunRuntimeContextResponse{
			Metadata: &managementv1.AgentRunRuntimeMetadata{
				CredentialId:       "cred-1",
				TargetHosts:        []string{"api.example.test"},
				TargetPathPrefixes: []string{"/v1"},
				RequestHeaderNames: []string{"authorization"},
				HeaderValuePrefix:  "Bearer",
			},
		},
	}
	server := &Server{agentSessions: runtimeContext}

	response, err := NewEgressExtAuthzServer(server).Check(context.Background(), extAuthzCheckRequest("10.0.0.12", "api.example.test:443", "/v1/chat/completions"))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := codes.Code(response.GetStatus().GetCode()), codes.Unavailable; got != want {
		t.Fatalf("status code = %v, want %v", got, want)
	}
	if got, want := response.GetDeniedResponse().GetStatus().GetCode(), typev3.StatusCode_BadGateway; got != want {
		t.Fatalf("http status = %v, want %v", got, want)
	}
}

func extAuthzCheckRequest(sourceIP string, host string, path string) *envoyauthv3.CheckRequest {
	return extAuthzCheckRequestWithPrincipal(sourceIP, "", host, path)
}

func extAuthzCheckRequestWithPrincipal(sourceIP string, principal string, host string, path string) *envoyauthv3.CheckRequest {
	return extAuthzCheckRequestWithPrincipalAndHeaders(sourceIP, principal, host, path, nil)
}

func extAuthzCheckRequestWithPrincipalAndHeaders(sourceIP string, principal string, host string, path string, extraHeaders map[string]string) *envoyauthv3.CheckRequest {
	var source *envoyauthv3.AttributeContext_Peer
	if sourceIP != "" {
		source = &envoyauthv3.AttributeContext_Peer{
			Principal: principal,
			Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
				Address: sourceIP,
				PortSpecifier: &corev3.SocketAddress_PortValue{
					PortValue: 41832,
				},
			}}},
		}
	}
	headers := map[string]string{
		":authority": host,
		":path":      path,
	}
	for key, value := range extraHeaders {
		headers[key] = value
	}
	return &envoyauthv3.CheckRequest{Attributes: &envoyauthv3.AttributeContext{
		Source: source,
		Request: &envoyauthv3.AttributeContext_Request{Http: &envoyauthv3.AttributeContext_HttpRequest{
			Host:    host,
			Path:    path,
			Headers: headers,
		}},
	}}
}
