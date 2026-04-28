package authservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	apiprotocolv1 "code-code.internal/go-contract/api_protocol/v1"
	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	providerv1 "code-code.internal/go-contract/provider/v1"
	"code-code.internal/platform-k8s/internal/egressauth"
	"google.golang.org/grpc"
)

type fakeCredentialResolver struct {
	credential *credentialv1.ResolvedCredential
	err        error
	grantID    string
}

func (r *fakeCredentialResolver) Resolve(_ context.Context, ref *credentialv1.CredentialGrantRef) (*credentialv1.ResolvedCredential, error) {
	if ref != nil {
		r.grantID = ref.GetGrantId()
	}
	return r.credential, r.err
}

type fakeRuntimeContextClient struct {
	request  *managementv1.ResolveAgentRunRuntimeContextRequest
	response *managementv1.ResolveAgentRunRuntimeContextResponse
	err      error
}

func (c *fakeRuntimeContextClient) ResolveAgentRunRuntimeContext(_ context.Context, request *managementv1.ResolveAgentRunRuntimeContextRequest, _ ...grpc.CallOption) (*managementv1.ResolveAgentRunRuntimeContextResponse, error) {
	c.request = request
	return c.response, c.err
}

type fakeProviderStore struct {
	providers []*providerv1.Provider
}

func (s fakeProviderStore) List(context.Context) ([]*providerv1.Provider, error) {
	return s.providers, nil
}

func (s fakeProviderStore) Get(context.Context, string) (*providerv1.Provider, error) {
	return nil, errors.New("unused")
}

func (s fakeProviderStore) Upsert(context.Context, *providerv1.Provider) (*providerv1.Provider, error) {
	return nil, errors.New("unused")
}

func (s fakeProviderStore) Update(context.Context, string, func(*providerv1.Provider) error) (*providerv1.Provider, error) {
	return nil, errors.New("unused")
}

func (s fakeProviderStore) Delete(context.Context, string) error {
	return errors.New("unused")
}

func TestEgressAuthHTTPHandlerReplacesBearerHeader(t *testing.T) {
	server := &Server{
		credentialResolver: &fakeCredentialResolver{
			credential: &credentialv1.ResolvedCredential{
				GrantId: "cred-1",
				Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
				Material: &credentialv1.ResolvedCredential_Oauth{
					Oauth: &credentialv1.OAuthCredential{AccessToken: "synthetic-token", TokenType: "Bearer"},
				},
			},
		},
	}
	body := []byte(`{
		"credentialId":"cred-1",
		"headerValuePrefix":"Bearer",
		"simpleReplacementRules":[{"mode":"bearer","headerName":"authorization"}],
		"headers":[{"name":"authorization","currentValue":"Bearer PLACEHOLDER"}]
	}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, egressAuthHeaderReplacementPath, bytes.NewReader(body))
	server.EgressAuthHTTPHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response egressAuthHeaderReplacementResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, want := httpHeaderMutationValue(response.Headers, "authorization"), "Bearer synthetic-token"; got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
	if len(response.RemoveHeaders) == 0 {
		t.Fatal("RemoveHeaders is empty")
	}
}

func TestResolveEgressRequestHeadersResolvesCredentialFromProviderSurfaceBinding(t *testing.T) {
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

	response, err := server.ResolveEgressRequestHeaders(context.Background(), &authv1.ResolveEgressRequestHeadersRequest{
		SourcePrincipal:          "spiffe://cluster.local/ns/code-code/sa/platform-model-service",
		ProviderSurfaceBindingId: "surface-1",
		TargetHost:               "api.example.test:443",
		TargetPath:               "/v1/models",
		HeaderValuePrefix:        "Bearer",
		AllowedHeaderNames:       []string{"authorization"},
		SimpleReplacementRules: []*authv1.EgressSimpleReplacementRule{{
			Mode:       egressauth.SimpleReplacementModeBearer,
			HeaderName: "authorization",
		}},
		Headers: []*authv1.EgressHeaderReplacementItem{{
			Name:         "authorization",
			CurrentValue: "Bearer " + egressauth.Placeholder,
		}},
	})
	if err != nil {
		t.Fatalf("ResolveEgressRequestHeaders() error = %v", err)
	}
	if got, want := resolver.grantID, "cred-1"; got != want {
		t.Fatalf("resolved credential id = %q, want %q", got, want)
	}
	if got, want := headerMutationValue(response.GetHeaders(), "authorization"), "Bearer surface-token"; got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
	if !containsHeaderName(response.GetRemoveHeaders(), egressauth.HeaderProviderSurfaceBindingID) {
		t.Fatalf("remove_headers = %v, want %s", response.GetRemoveHeaders(), egressauth.HeaderProviderSurfaceBindingID)
	}
}

func TestResolveEgressRequestHeadersUsesObservabilityCredentialForSessionAdapter(t *testing.T) {
	resolver := &fakeCredentialResolver{
		credential: &credentialv1.ResolvedCredential{
			GrantId: "provider-1-observability",
			Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
			Material: &credentialv1.ResolvedCredential_Session{
				Session: &credentialv1.SessionCredential{Values: map[string]string{
					"authjs_session_token": "session-token",
				}},
			},
		},
	}
	server := &Server{
		namespace:          "code-code",
		providers:          fakeProviderStore{providers: []*providerv1.Provider{providerWithSurface("provider-1", "surface-1", "primary-cred", "https://cloud.cerebras.ai/api/graphql")}},
		credentialResolver: resolver,
	}

	response, err := server.ResolveEgressRequestHeaders(context.Background(), &authv1.ResolveEgressRequestHeadersRequest{
		AdapterId:                egressauth.AuthAdapterSessionCookieID,
		SourcePrincipal:          "spiffe://cluster.local/ns/code-code/sa/platform-provider-service",
		ProviderSurfaceBindingId: "surface-1",
		TargetHost:               "cloud.cerebras.ai:443",
		TargetPath:               "/api/graphql",
		AllowedHeaderNames:       []string{"cookie"},
		SimpleReplacementRules: []*authv1.EgressSimpleReplacementRule{{
			Mode:       egressauth.SimpleReplacementModeCookie,
			HeaderName: "cookie",
		}},
		Headers: []*authv1.EgressHeaderReplacementItem{{
			Name:         "cookie",
			CurrentValue: "authjs.session-token=" + egressauth.Placeholder,
		}},
	})
	if err != nil {
		t.Fatalf("ResolveEgressRequestHeaders() error = %v", err)
	}
	if got, want := resolver.grantID, "provider-1-observability"; got != want {
		t.Fatalf("resolved credential id = %q, want %q", got, want)
	}
	if got, want := headerMutationValue(response.GetHeaders(), "cookie"), "authjs.session-token=session-token"; got != want {
		t.Fatalf("cookie = %q, want %q", got, want)
	}
}

func TestResolveEgressRequestHeadersResolvesCredentialFromRuntimeSource(t *testing.T) {
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

	response, err := server.ResolveEgressRequestHeaders(context.Background(), &authv1.ResolveEgressRequestHeadersRequest{
		CredentialId: "forged-credential",
		RuntimeSource: &authv1.EgressRequestSource{Source: &authv1.EgressRequestSource_Pod{Pod: &authv1.EgressPodSource{
			Namespace: "code-code-runs",
			Ip:        "10.0.0.12",
		}}},
		TargetHost: "api.example.test:443",
		TargetPath: "/v1/chat/completions",
	})
	if err != nil {
		t.Fatalf("ResolveEgressRequestHeaders() error = %v", err)
	}
	if got, want := runtimeContext.request.GetPod().GetIp(), "10.0.0.12"; got != want {
		t.Fatalf("runtime source pod.ip = %q, want %q", got, want)
	}
	if got, want := headerMutationValue(response.GetHeaders(), "authorization"), "Bearer synthetic-token"; got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
	if got, want := server.credentialResolver.(*fakeCredentialResolver).grantID, "cred-1"; got != want {
		t.Fatalf("resolved credential id = %q, want %q", got, want)
	}
}

func TestResolveEgressRequestHeadersSkipsRuntimeSourceTargetMismatch(t *testing.T) {
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
	server := &Server{agentSessions: runtimeContext}

	response, err := server.ResolveEgressRequestHeaders(context.Background(), &authv1.ResolveEgressRequestHeadersRequest{
		RuntimeSource: &authv1.EgressRequestSource{Source: &authv1.EgressRequestSource_Pod{Pod: &authv1.EgressPodSource{
			Ip: "10.0.0.12",
		}}},
		TargetHost: "other.example.test",
		TargetPath: "/v1/chat/completions",
		Headers: []*authv1.EgressHeaderReplacementItem{{
			Name:         "authorization",
			CurrentValue: "Bearer PLACEHOLDER",
		}},
	})
	if err != nil {
		t.Fatalf("ResolveEgressRequestHeaders() error = %v", err)
	}
	if !response.GetSkipped() {
		t.Fatalf("skipped = false, response = %#v", response)
	}
	if containsHeaderName(response.GetRemoveHeaders(), "authorization") {
		t.Fatalf("remove_headers = %v", response.GetRemoveHeaders())
	}
}

func TestResolveEgressRequestHeadersSkipsRuntimeSourceWithoutAuthMetadata(t *testing.T) {
	runtimeContext := &fakeRuntimeContextClient{
		response: &managementv1.ResolveAgentRunRuntimeContextResponse{
			Metadata: &managementv1.AgentRunRuntimeMetadata{},
		},
	}
	server := &Server{agentSessions: runtimeContext}

	response, err := server.ResolveEgressRequestHeaders(context.Background(), &authv1.ResolveEgressRequestHeadersRequest{
		RuntimeSource: &authv1.EgressRequestSource{Source: &authv1.EgressRequestSource_Pod{Pod: &authv1.EgressPodSource{
			Ip: "10.0.0.12",
		}}},
		TargetHost: "api.example.test",
		TargetPath: "/v1/chat/completions",
	})
	if err != nil {
		t.Fatalf("ResolveEgressRequestHeaders() error = %v", err)
	}
	if !response.GetSkipped() {
		t.Fatalf("skipped = false, response = %#v", response)
	}
}

func TestResolveEgressResponseHeadersSanitizesRuntimeSource(t *testing.T) {
	runtimeContext := &fakeRuntimeContextClient{
		response: &managementv1.ResolveAgentRunRuntimeContextResponse{
			Metadata: &managementv1.AgentRunRuntimeMetadata{
				CredentialId:       "cred-1",
				TargetHosts:        []string{"accounts.example.test"},
				TargetPathPrefixes: []string{"/oauth"},
				ResponseHeaderReplacementRules: []*managementv1.AgentRunRuntimeHeaderReplacementRule{{
					HeaderName:  "set-cookie",
					MaterialKey: "session_id",
					Template:    "SID=PLACEHOLDER",
				}},
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
						"session_id": "session-secret",
					}},
				},
			},
		},
	}

	response, err := server.ResolveEgressResponseHeaders(context.Background(), &authv1.ResolveEgressResponseHeadersRequest{
		RuntimeSource: &authv1.EgressRequestSource{Source: &authv1.EgressRequestSource_Pod{Pod: &authv1.EgressPodSource{
			Ip: "10.0.0.12",
		}}},
		TargetHost: "accounts.example.test",
		TargetPath: "/oauth/callback",
		Headers: []*authv1.EgressHeaderReplacementItem{{
			Name:         "set-cookie",
			CurrentValue: "SID=session-secret; Path=/; Secure",
		}},
	})
	if err != nil {
		t.Fatalf("ResolveEgressResponseHeaders() error = %v", err)
	}
	if got, want := headerMutationValue(response.GetHeaders(), "set-cookie"), "SID=PLACEHOLDER; Path=/; Secure"; got != want {
		t.Fatalf("set-cookie = %q, want %q", got, want)
	}
	if got, want := response.GetHeaders()[0].GetAppendAction(), authv1.EgressHeaderAppendAction_EGRESS_HEADER_APPEND_ACTION_APPEND_IF_EXISTS_OR_ADD; got != want {
		t.Fatalf("set-cookie append_action = %v, want %v", got, want)
	}
}

func TestResolveEgressResponseHeadersPreservesMultipleSetCookieHeaders(t *testing.T) {
	server := &Server{
		credentialResolver: &fakeCredentialResolver{
			credential: &credentialv1.ResolvedCredential{
				GrantId: "cred-1",
				Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
				Material: &credentialv1.ResolvedCredential_Session{
					Session: &credentialv1.SessionCredential{Values: map[string]string{
						"sid":  "session-secret",
						"hsid": "host-secret",
					}},
				},
			},
		},
	}

	response, err := server.ResolveEgressResponseHeaders(context.Background(), &authv1.ResolveEgressResponseHeadersRequest{
		CredentialId: "cred-1",
		SimpleReplacementRules: []*authv1.EgressSimpleReplacementRule{{
			HeaderName:  "set-cookie",
			MaterialKey: "sid",
			Template:    "SID=PLACEHOLDER",
		}, {
			HeaderName:  "set-cookie",
			MaterialKey: "hsid",
			Template:    "HSID=PLACEHOLDER",
		}},
		AllowedHeaderNames: []string{"set-cookie"},
		Headers: []*authv1.EgressHeaderReplacementItem{{
			Name:         "set-cookie",
			CurrentValue: "SID=session-secret; Path=/; Secure",
		}, {
			Name:         "set-cookie",
			CurrentValue: "HSID=host-secret; Path=/; Secure",
		}},
	})
	if err != nil {
		t.Fatalf("ResolveEgressResponseHeaders() error = %v", err)
	}
	values := headerMutationValues(response.GetHeaders(), "set-cookie")
	if got, want := len(values), 2; got != want {
		t.Fatalf("set-cookie values len = %d, want %d: %v", got, want, values)
	}
	if values[0] != "SID=PLACEHOLDER; Path=/; Secure" || values[1] != "HSID=PLACEHOLDER; Path=/; Secure" {
		t.Fatalf("set-cookie values = %v", values)
	}
	for _, header := range response.GetHeaders() {
		if got, want := header.GetAppendAction(), authv1.EgressHeaderAppendAction_EGRESS_HEADER_APPEND_ACTION_APPEND_IF_EXISTS_OR_ADD; got != want {
			t.Fatalf("append_action = %v, want %v", got, want)
		}
	}
}

func TestResolveEgressResponseHeadersSanitizesControlPlaneTemplate(t *testing.T) {
	server := &Server{
		credentialResolver: &fakeCredentialResolver{
			credential: &credentialv1.ResolvedCredential{
				GrantId: "cred-1",
				Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
				Material: &credentialv1.ResolvedCredential_Oauth{
					Oauth: &credentialv1.OAuthCredential{AccessToken: "response-token"},
				},
			},
		},
	}

	response, err := server.ResolveEgressResponseHeaders(context.Background(), &authv1.ResolveEgressResponseHeadersRequest{
		CredentialId: "cred-1",
		SimpleReplacementRules: []*authv1.EgressSimpleReplacementRule{{
			HeaderName:  "authorization",
			MaterialKey: "access_token",
			Template:    "Bearer PLACEHOLDER",
		}},
		AllowedHeaderNames: []string{"authorization"},
		Headers: []*authv1.EgressHeaderReplacementItem{{
			Name:         "authorization",
			CurrentValue: "Bearer response-token",
		}},
	})
	if err != nil {
		t.Fatalf("ResolveEgressResponseHeaders() error = %v", err)
	}
	if got, want := headerMutationValue(response.GetHeaders(), "authorization"), "Bearer PLACEHOLDER"; got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
}

func TestEgressAuthHTTPHandlerGoogleAIStudioAdapter(t *testing.T) {
	server := &Server{
		credentialResolver: &fakeCredentialResolver{
			credential: &credentialv1.ResolvedCredential{
				GrantId: "cred-1",
				Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
				Material: &credentialv1.ResolvedCredential_Session{
					Session: &credentialv1.SessionCredential{Values: map[string]string{
						"page_api_key": "page-key",
						"cookie":       "SAPISID=sapisid",
					}},
				},
			},
		},
	}
	body := []byte(`{
		"credentialId":"cred-1",
		"adapterId":"google-aistudio-session",
		"headers":[{"name":"x-goog-api-key","currentValue":"PLACEHOLDER"}]
	}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, egressAuthHeaderReplacementPath, bytes.NewReader(body))
	server.EgressAuthHTTPHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response egressAuthHeaderReplacementResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, want := httpHeaderMutationValue(response.Headers, "x-goog-api-key"), "page-key"; got != want {
		t.Fatalf("x-goog-api-key = %q, want %q", got, want)
	}
}

func TestEgressAuthHTTPHandlerUsesDeclarativeSimpleRule(t *testing.T) {
	server := &Server{
		credentialResolver: &fakeCredentialResolver{
			credential: &credentialv1.ResolvedCredential{
				GrantId: "cred-1",
				Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
				Material: &credentialv1.ResolvedCredential_Oauth{
					Oauth: &credentialv1.OAuthCredential{
						AccessToken: "access-token",
						IdToken:     "id-token",
					},
				},
			},
		},
	}
	body := []byte(`{
		"credentialId":"cred-1",
		"simpleReplacementRules":[{"headerName":"authorization","materialKey":"id_token","template":"Bearer PLACEHOLDER"}],
		"headers":[{"name":"authorization","currentValue":"PLACEHOLDER"}]
	}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, egressAuthHeaderReplacementPath, bytes.NewReader(body))
	server.EgressAuthHTTPHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response egressAuthHeaderReplacementResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, want := httpHeaderMutationValue(response.Headers, "authorization"), "Bearer id-token"; got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
}

func TestEgressAuthHTTPHandlerDoesNotEchoMaterialOnFailure(t *testing.T) {
	server := &Server{
		credentialResolver: &fakeCredentialResolver{
			credential: &credentialv1.ResolvedCredential{
				GrantId:  "cred-1",
				Kind:     credentialv1.CredentialKind_CREDENTIAL_KIND_API_KEY,
				Material: &credentialv1.ResolvedCredential_ApiKey{ApiKey: &credentialv1.ApiKeyCredential{ApiKey: "synthetic-secret"}},
			},
		},
	}
	body := []byte(`{
		"credentialId":"cred-1",
		"headers":[{"name":"authorization","currentValue":"no-placeholder"}]
	}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, egressAuthHeaderReplacementPath, bytes.NewReader(body))
	server.EgressAuthHTTPHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("synthetic-secret")) || bytes.Contains(recorder.Body.Bytes(), []byte(egressauth.Placeholder)) {
		t.Fatalf("failure response leaked sensitive material: %s", recorder.Body.String())
	}
}

func containsHeaderName(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func headerMutationValue(headers []*authv1.EgressHeaderMutation, name string) string {
	values := headerMutationValues(headers, name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func headerMutationValues(headers []*authv1.EgressHeaderMutation, name string) []string {
	name = normalizeHTTPHeaderName(name)
	values := []string{}
	for _, header := range headers {
		if header == nil || normalizeHTTPHeaderName(header.GetName()) != name {
			continue
		}
		values = append(values, header.GetValue())
	}
	return values
}

func httpHeaderMutationValue(headers []egressAuthHeaderMutation, name string) string {
	name = normalizeHTTPHeaderName(name)
	for _, header := range headers {
		if normalizeHTTPHeaderName(header.Name) == name {
			return header.Value
		}
	}
	return ""
}

func providerWithSurface(providerID string, surfaceID string, credentialID string, baseURL string) *providerv1.Provider {
	return &providerv1.Provider{
		ProviderId: providerID,
		Surfaces: []*providerv1.ProviderSurfaceBinding{{
			SurfaceId: surfaceID,
			ProviderCredentialRef: &providerv1.ProviderCredentialRef{
				ProviderCredentialId: credentialID,
			},
			Runtime: &providerv1.ProviderSurfaceRuntime{
				Access: &providerv1.ProviderSurfaceRuntime_Api{Api: &providerv1.ProviderAPISurfaceRuntime{
					Protocol: apiprotocolv1.Protocol_PROTOCOL_OPENAI_COMPATIBLE,
					BaseUrl:  baseURL,
				}},
			},
		}},
	}
}
