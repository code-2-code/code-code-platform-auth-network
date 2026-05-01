package authservice

import (
	"context"
	"net/http"
	"strings"
	"testing"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	"code-code.internal/platform-k8s/internal/egressauth"
	"code-code.internal/platform-k8s/internal/egressauthpolicy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func TestResolveEgressRequestHeadersResolvesCredentialFromAuthPolicyMatch(t *testing.T) {
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
		credentialResolver: resolver,
		headerRewritePolicies: mustHeaderRewritePolicies(t, `
policies:
  - policyId: test.workload-bearer
    source:
      serviceAccounts:
        - code-code/platform-observability-runner
    target:
      hosts:
        - api.example.test
      pathPrefixes:
        - /v1
      methods:
        - GET
    materializations:
      - materializationKey: test.workload-bearer
        credentialId: cred-1
        requestReplacementRules:
          - mode: bearer
            headerName: authorization
            materialKey: access_token
            headerValuePrefix: Bearer
`),
	}

	response, err := server.ResolveEgressRequestHeaders(context.Background(), &authv1.ResolveEgressRequestHeadersRequest{
		SourcePrincipal: "spiffe://cluster.local/ns/code-code/sa/platform-observability-runner",
		TargetHost:      "api.example.test:443",
		TargetPath:      "/v1/models",
		TargetMethod:    http.MethodGet,
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
}

func TestResolveEgressRequestHeadersUsesAuthPolicyCredentialForSessionAdapter(t *testing.T) {
	resolver := &fakeCredentialResolver{
		credential: &credentialv1.ResolvedCredential{
			GrantId: "credential-observability",
			Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
			Material: &credentialv1.ResolvedCredential_Session{
				Session: &credentialv1.SessionCredential{Values: map[string]string{
					"authjs_session_token": "session-token",
				}},
			},
		},
	}
	server := &Server{
		credentialResolver: resolver,
		headerRewritePolicies: mustHeaderRewritePolicies(t, `
policies:
  - policyId: test.authjs-session
    adapterId: session-cookie
    source:
      serviceAccounts:
        - code-code/platform-observability-runner
    target:
      hosts:
        - cloud.cerebras.ai
      pathPrefixes:
        - /api/graphql
    materializations:
      - materializationKey: test.authjs-session
        credentialId: credential-observability
        requestReplacementRules:
          - mode: cookie
            headerName: cookie
            materialKey: authjs_session_token
            template: authjs.session-token=PLACEHOLDER
`),
	}

	response, err := server.ResolveEgressRequestHeaders(context.Background(), &authv1.ResolveEgressRequestHeadersRequest{
		SourcePrincipal: "spiffe://cluster.local/ns/code-code/sa/platform-observability-runner",
		TargetHost:      "cloud.cerebras.ai:443",
		TargetPath:      "/api/graphql",
	})
	if err != nil {
		t.Fatalf("ResolveEgressRequestHeaders() error = %v", err)
	}
	if got, want := resolver.grantID, "credential-observability"; got != want {
		t.Fatalf("resolved credential id = %q, want %q", got, want)
	}
	if got, want := headerMutationValue(response.GetHeaders(), "cookie"), "authjs.session-token=session-token"; got != want {
		t.Fatalf("cookie = %q, want %q", got, want)
	}
}

func TestResolveEgressRequestHeadersGeneratesGoogleAIStudioHeadersFromAuthPolicy(t *testing.T) {
	resolver := &fakeCredentialResolver{
		credential: &credentialv1.ResolvedCredential{
			GrantId: "credential-observability",
			Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
			Material: &credentialv1.ResolvedCredential_Session{
				Session: &credentialv1.SessionCredential{Values: map[string]string{
					"cookie": "SAPISID=sapisid; __Secure-1PAPISID=one; __Secure-3PAPISID=three",
				}},
			},
		},
	}
	server := &Server{
		credentialResolver: resolver,
		headerRewritePolicies: mustHeaderRewritePolicies(t, `
policies:
  - policyId: test.google-aistudio-session
    adapterId: google-aistudio-session
    source:
      serviceAccounts:
        - code-code/platform-observability-runner
    target:
      hosts:
        - alkalimakersuite-pa.clients6.google.com
      pathPrefixes:
        - /$rpc/google.internal.alkali.applications.makersuite.v1.MakerSuiteService/
      methods:
        - POST
    materializations:
      - materializationKey: test.google-aistudio-session
        credentialId: credential-observability
        requestReplacementRules:
          - headerName: authorization
          - headerName: cookie
          - headerName: x-goog-api-key
`),
	}

	response, err := server.ResolveEgressRequestHeaders(context.Background(), &authv1.ResolveEgressRequestHeadersRequest{
		SourcePrincipal: "spiffe://cluster.local/ns/code-code/sa/platform-observability-runner",
		TargetHost:      "alkalimakersuite-pa.clients6.google.com:443",
		TargetPath:      "/$rpc/google.internal.alkali.applications.makersuite.v1.MakerSuiteService/ListModelRateLimits",
		TargetMethod:    http.MethodPost,
		RequestHeaders: map[string]string{
			"origin": "https://aistudio.google.com",
		},
	})
	if err != nil {
		t.Fatalf("ResolveEgressRequestHeaders() error = %v", err)
	}
	if got, want := resolver.grantID, "credential-observability"; got != want {
		t.Fatalf("resolved credential id = %q, want %q", got, want)
	}
	if got := headerMutationValue(response.GetHeaders(), "authorization"); !strings.Contains(got, "SAPISIDHASH ") || strings.Contains(got, egressauth.Placeholder) {
		t.Fatalf("authorization = %q, want generated SAPISIDHASH without placeholder", got)
	}
	if got, want := headerMutationValue(response.GetHeaders(), "cookie"), "SAPISID=sapisid; __Secure-1PAPISID=one; __Secure-3PAPISID=three"; got != want {
		t.Fatalf("cookie = %q, want %q", got, want)
	}
	if got, want := headerMutationValue(response.GetHeaders(), "x-goog-api-key"), "AIzaSyDdP816MREB3SkjZO04QXbjsigfcI0GWOs"; got != want {
		t.Fatalf("x-goog-api-key = %q, want %q", got, want)
	}
}

func TestResolveEgressRequestHeadersGeneratesMistralAdminHeadersFromAuthPolicy(t *testing.T) {
	resolver := &fakeCredentialResolver{
		credential: &credentialv1.ResolvedCredential{
			GrantId: "credential-observability",
			Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
			Material: &credentialv1.ResolvedCredential_Session{
				Session: &credentialv1.SessionCredential{Values: map[string]string{
					"cookie": "ory_session_test=abc; csrftoken=csrf-1",
				}},
			},
		},
	}
	server := &Server{
		credentialResolver: resolver,
		headerRewritePolicies: mustHeaderRewritePolicies(t, `
policies:
  - policyId: test.mistral-admin-session
    adapterId: mistral-admin-session
    source:
      serviceAccounts:
        - code-code/platform-observability-runner
    target:
      hosts:
        - admin.mistral.ai
      pathPrefixes:
        - /api/billing/
      methods:
        - GET
    materializations:
      - materializationKey: test.mistral-admin-session
        credentialId: credential-observability
        requestReplacementRules:
          - headerName: cookie
          - headerName: x-csrftoken
`),
	}

	response, err := server.ResolveEgressRequestHeaders(context.Background(), &authv1.ResolveEgressRequestHeadersRequest{
		SourcePrincipal: "spiffe://cluster.local/ns/code-code/sa/platform-observability-runner",
		TargetHost:      "admin.mistral.ai:443",
		TargetPath:      "/api/billing/v2/usage",
		TargetMethod:    http.MethodGet,
	})
	if err != nil {
		t.Fatalf("ResolveEgressRequestHeaders() error = %v", err)
	}
	if got, want := resolver.grantID, "credential-observability"; got != want {
		t.Fatalf("resolved credential id = %q, want %q", got, want)
	}
	if got, want := headerMutationValue(response.GetHeaders(), "cookie"), "ory_session_test=abc; csrftoken=csrf-1"; got != want {
		t.Fatalf("cookie = %q, want %q", got, want)
	}
	if got, want := headerMutationValue(response.GetHeaders(), "x-csrftoken"), "csrf-1"; got != want {
		t.Fatalf("x-csrftoken = %q, want %q", got, want)
	}
}

func TestResolveEgressRequestHeadersReportsGoogleAIStudioMissingAuthorizationMaterial(t *testing.T) {
	resolver := &fakeCredentialResolver{
		credential: &credentialv1.ResolvedCredential{
			GrantId: "credential-observability",
			Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
			Material: &credentialv1.ResolvedCredential_Session{
				Session: &credentialv1.SessionCredential{Values: map[string]string{
					"cookie": "SID=session-only",
				}},
			},
		},
	}
	server := &Server{
		credentialResolver: resolver,
		headerRewritePolicies: mustHeaderRewritePolicies(t, `
policies:
  - policyId: test.google-aistudio-session
    adapterId: google-aistudio-session
    source:
      serviceAccounts:
        - code-code/platform-observability-runner
    target:
      hosts:
        - alkalimakersuite-pa.clients6.google.com
      pathPrefixes:
        - /$rpc/google.internal.alkali.applications.makersuite.v1.MakerSuiteService/
      methods:
        - POST
    materializations:
      - materializationKey: test.google-aistudio-session
        credentialId: credential-observability
        requestReplacementRules:
          - headerName: authorization
          - headerName: cookie
          - headerName: x-goog-api-key
`),
	}

	_, err := server.ResolveEgressRequestHeaders(context.Background(), &authv1.ResolveEgressRequestHeadersRequest{
		SourcePrincipal: "spiffe://cluster.local/ns/code-code/sa/platform-observability-runner",
		TargetHost:      "alkalimakersuite-pa.clients6.google.com:443",
		TargetPath:      "/$rpc/google.internal.alkali.applications.makersuite.v1.MakerSuiteService/ListModelRateLimits",
		TargetMethod:    http.MethodPost,
		RequestHeaders: map[string]string{
			"origin": "https://aistudio.google.com",
		},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ResolveEgressRequestHeaders() code = %v, want %v, err=%v", status.Code(err), codes.FailedPrecondition, err)
	}
	if !strings.Contains(err.Error(), `header "authorization"`) {
		t.Fatalf("ResolveEgressRequestHeaders() error = %q, want authorization header context", err.Error())
	}
	if strings.Contains(err.Error(), "SID=session-only") {
		t.Fatalf("ResolveEgressRequestHeaders() error leaks material: %q", err.Error())
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

func TestResolveEgressResponseHeadersRemovesUnmatchedSetCookie(t *testing.T) {
	server := &Server{
		credentialResolver: &fakeCredentialResolver{
			credential: &credentialv1.ResolvedCredential{
				GrantId: "cred-1",
				Kind:    credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
				Material: &credentialv1.ResolvedCredential_Session{
					Session: &credentialv1.SessionCredential{Values: map[string]string{
						"sid": "session-secret",
					}},
				},
			},
		},
	}

	response, err := server.ResolveEgressResponseHeaders(context.Background(), &authv1.ResolveEgressResponseHeadersRequest{
		CredentialId:       "cred-1",
		AllowedHeaderNames: []string{"set-cookie"},
		Headers: []*authv1.EgressHeaderReplacementItem{{
			Name:         "set-cookie",
			CurrentValue: "OTHER=new-secret; Path=/; Secure",
		}},
	})
	if err != nil {
		t.Fatalf("ResolveEgressResponseHeaders() error = %v", err)
	}
	if len(response.GetHeaders()) != 0 {
		t.Fatalf("headers = %v, want empty", response.GetHeaders())
	}
	if !containsHeaderName(response.GetRemoveHeaders(), "set-cookie") {
		t.Fatalf("remove_headers = %v, want set-cookie", response.GetRemoveHeaders())
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

func mustHeaderRewritePolicies(t *testing.T, raw string) *egressauthpolicy.Catalog {
	t.Helper()
	catalog, err := egressauthpolicy.LoadCatalog([]byte(raw))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	return catalog
}
