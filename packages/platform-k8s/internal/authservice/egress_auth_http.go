package authservice

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	providerv1 "code-code.internal/go-contract/provider/v1"
	"code-code.internal/platform-k8s/internal/egressauth"
	"code-code.internal/platform-k8s/internal/egressauth/adapters/googleaistudio"
	"code-code.internal/platform-k8s/internal/platform/provideridentity"
	"code-code.internal/platform-k8s/internal/providerservice/providers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	egressAuthHeaderReplacementPath         = "/internal/egress-auth/header-replacement"
	egressAuthResponseHeaderReplacementPath = "/internal/egress-auth/response-header-replacement"
	egressAuthMaxRequestBytes               = 32 << 10
	egressAuthResolveTimeout                = 3 * time.Second
)

type egressAuthHeaderReplacementRequest struct {
	CredentialID           string                             `json:"credentialId"`
	AdapterID              string                             `json:"adapterId,omitempty"`
	TargetHost             string                             `json:"targetHost,omitempty"`
	TargetPath             string                             `json:"targetPath,omitempty"`
	HeaderValuePrefix      string                             `json:"headerValuePrefix,omitempty"`
	Origin                 string                             `json:"origin,omitempty"`
	RequestHeaders         map[string]string                  `json:"requestHeaders,omitempty"`
	SimpleReplacementRules []egressauth.SimpleReplacementRule `json:"simpleReplacementRules,omitempty"`
	Headers                []egressAuthHeaderReplacementItem  `json:"headers"`
}

type egressAuthResponseHeaderReplacementRequest struct {
	CredentialID           string                             `json:"credentialId"`
	AdapterID              string                             `json:"adapterId,omitempty"`
	TargetHost             string                             `json:"targetHost,omitempty"`
	TargetPath             string                             `json:"targetPath,omitempty"`
	HeaderValuePrefix      string                             `json:"headerValuePrefix,omitempty"`
	Origin                 string                             `json:"origin,omitempty"`
	StatusCode             uint32                             `json:"statusCode,omitempty"`
	RequestHeaders         map[string]string                  `json:"requestHeaders,omitempty"`
	ResponseHeaders        map[string]string                  `json:"responseHeaders,omitempty"`
	SimpleReplacementRules []egressauth.SimpleReplacementRule `json:"simpleReplacementRules,omitempty"`
	Headers                []egressAuthHeaderReplacementItem  `json:"headers"`
}

type egressAuthHeaderReplacementItem struct {
	Name         string `json:"name"`
	CurrentValue string `json:"currentValue"`
}

type egressAuthHeaderReplacementResponse struct {
	Headers       []egressAuthHeaderMutation `json:"headers,omitempty"`
	RemoveHeaders []string                   `json:"removeHeaders,omitempty"`
	Error         string                     `json:"error,omitempty"`
	Skipped       bool                       `json:"skipped,omitempty"`
}

type egressAuthHeaderMutation struct {
	Name         string `json:"name"`
	Value        string `json:"value"`
	AppendAction string `json:"appendAction,omitempty"`
}

func (s *Server) EgressAuthHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(egressAuthHeaderReplacementPath, s.handleEgressAuthHeaderReplacement)
	mux.HandleFunc(egressAuthResponseHeaderReplacementPath, s.handleEgressAuthResponseHeaderReplacement)
	return mux
}

func (s *Server) handleEgressAuthHeaderReplacement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeEgressAuthError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request egressAuthHeaderReplacementRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, egressAuthMaxRequestBytes))
	if err := decoder.Decode(&request); err != nil {
		writeEgressAuthError(w, http.StatusBadRequest, "invalid egress auth replacement request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), egressAuthResolveTimeout)
	defer cancel()
	response, err := s.ResolveEgressRequestHeaders(ctx, httpEgressAuthRequestToProto(request))
	if err != nil {
		writeEgressAuthError(w, httpStatusForEgressAuthError(err), "egress auth replacement failed")
		return
	}
	writeEgressAuthJSON(w, http.StatusOK, egressAuthHeaderReplacementResponse{
		Headers:       httpHeaderMutationsFromProto(response.GetHeaders()),
		RemoveHeaders: response.GetRemoveHeaders(),
		Error:         response.GetError(),
		Skipped:       response.GetSkipped(),
	})
}

func (s *Server) handleEgressAuthResponseHeaderReplacement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeEgressAuthError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request egressAuthResponseHeaderReplacementRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, egressAuthMaxRequestBytes))
	if err := decoder.Decode(&request); err != nil {
		writeEgressAuthError(w, http.StatusBadRequest, "invalid egress auth response replacement request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), egressAuthResolveTimeout)
	defer cancel()
	response, err := s.ResolveEgressResponseHeaders(ctx, httpEgressAuthResponseRequestToProto(request))
	if err != nil {
		writeEgressAuthError(w, httpStatusForEgressAuthError(err), "egress auth response replacement failed")
		return
	}
	writeEgressAuthJSON(w, http.StatusOK, egressAuthHeaderReplacementResponse{
		Headers:       httpHeaderMutationsFromProto(response.GetHeaders()),
		RemoveHeaders: response.GetRemoveHeaders(),
		Error:         response.GetError(),
		Skipped:       response.GetSkipped(),
	})
}

func (s *Server) ResolveEgressRequestHeaders(ctx context.Context, request *authv1.ResolveEgressRequestHeadersRequest) (*authv1.ResolveEgressRequestHeadersResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid egress auth replacement request")
	}
	request.CredentialId = strings.TrimSpace(request.GetCredentialId())
	request.TargetHost = strings.TrimSpace(request.GetTargetHost())
	request.TargetPath = strings.TrimSpace(request.GetTargetPath())
	request.SourcePrincipal = strings.TrimSpace(request.GetSourcePrincipal())
	request.ProviderSurfaceBindingId = strings.TrimSpace(request.GetProviderSurfaceBindingId())
	request.EgressPolicyId = strings.TrimSpace(request.GetEgressPolicyId())
	request.AuthPolicyId = strings.TrimSpace(request.GetAuthPolicyId())
	runtimeRequest := request.GetRuntimeSource() != nil
	if !runtimeRequest && request.GetProviderSurfaceBindingId() == "" && len(request.GetHeaders()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid egress auth replacement request")
	}
	if runtimeRequest {
		metadata, err := s.resolveEgressRuntimeMetadata(ctx, request.GetRuntimeSource())
		if err != nil {
			if status.Code(err) == codes.NotFound {
				return skippedEgressRequestAuthResponse(), nil
			}
			return nil, err
		}
		if response, err := applyEgressRuntimeMetadata(request, metadata); response != nil || err != nil {
			return response, err
		}
	} else if request.GetProviderSurfaceBindingId() != "" {
		if err := s.applyEgressProviderSurfaceBinding(ctx, request); err != nil {
			return nil, err
		}
	}
	if request.GetCredentialId() == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid egress auth replacement request")
	}
	resolver := s.credentialResolver
	if resolver == nil {
		return nil, status.Error(codes.Unavailable, "egress auth replacement unavailable")
	}
	credential, err := resolver.Resolve(ctx, &credentialv1.CredentialGrantRef{GrantId: request.GetCredentialId()})
	if err != nil {
		return nil, status.Error(codes.Unavailable, "egress auth replacement failed")
	}
	material := materialFromResolvedCredential(credential)
	if runtimeRequest || len(request.GetHeaders()) == 0 {
		return resolveGeneratedEgressHeaders(request, material)
	}
	allowedHeaders := headerNameSet(request.GetAllowedHeaderNames())
	simpleRules := protoSimpleReplacementRules(request.GetSimpleReplacementRules())
	headers := map[string]string{}
	for _, item := range request.GetHeaders() {
		name := normalizeHTTPHeaderName(item.GetName())
		current := strings.TrimSpace(item.GetCurrentValue())
		if len(allowedHeaders) > 0 {
			if _, ok := allowedHeaders[name]; !ok {
				continue
			}
		}
		if name == "" || !strings.Contains(current, egressauth.Placeholder) {
			continue
		}
		next, ok := replaceEgressAuthHeader(request, simpleRules, material, name, current)
		if !ok {
			return nil, status.Error(codes.FailedPrecondition, "egress auth replacement failed")
		}
		headers[name] = next
	}
	if len(headers) == 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid egress auth replacement request")
	}
	return &authv1.ResolveEgressRequestHeadersResponse{
		Headers:       requestHeaderMutationsFromMap(headers),
		RemoveHeaders: egressauth.InternalHeaders(),
	}, nil
}

func (s *Server) ResolveEgressResponseHeaders(ctx context.Context, request *authv1.ResolveEgressResponseHeadersRequest) (*authv1.ResolveEgressResponseHeadersResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid egress auth response replacement request")
	}
	request.CredentialId = strings.TrimSpace(request.GetCredentialId())
	request.TargetHost = strings.TrimSpace(request.GetTargetHost())
	request.TargetPath = strings.TrimSpace(request.GetTargetPath())
	request.SourcePrincipal = strings.TrimSpace(request.GetSourcePrincipal())
	request.ProviderSurfaceBindingId = strings.TrimSpace(request.GetProviderSurfaceBindingId())
	request.EgressPolicyId = strings.TrimSpace(request.GetEgressPolicyId())
	request.AuthPolicyId = strings.TrimSpace(request.GetAuthPolicyId())
	runtimeRequest := request.GetRuntimeSource() != nil
	if runtimeRequest {
		metadata, err := s.resolveEgressRuntimeMetadata(ctx, request.GetRuntimeSource())
		if err != nil {
			if status.Code(err) == codes.NotFound {
				return skippedEgressResponseAuthResponse(), nil
			}
			return nil, err
		}
		if response, err := applyEgressRuntimeResponseMetadata(request, metadata); response != nil || err != nil {
			return response, err
		}
	} else if request.GetProviderSurfaceBindingId() != "" {
		if err := s.applyEgressProviderSurfaceBindingForResponse(ctx, request); err != nil {
			return nil, err
		}
	}
	if request.GetCredentialId() == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid egress auth response replacement request")
	}
	resolver := s.credentialResolver
	if resolver == nil {
		return nil, status.Error(codes.Unavailable, "egress auth replacement unavailable")
	}
	credential, err := resolver.Resolve(ctx, &credentialv1.CredentialGrantRef{GrantId: request.GetCredentialId()})
	if err != nil {
		return nil, status.Error(codes.Unavailable, "egress auth replacement failed")
	}
	material := materialFromResolvedCredential(credential)
	response, err := resolveEgressResponseHeaders(request, material)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func resolveGeneratedEgressHeaders(request *authv1.ResolveEgressRequestHeadersRequest, material map[string]string) (*authv1.ResolveEgressRequestHeadersResponse, error) {
	allowedHeaders := normalizedHeaderNames(request.GetAllowedHeaderNames())
	rules := protoSimpleReplacementRules(request.GetSimpleReplacementRules())
	if len(allowedHeaders) == 0 && len(rules) > 0 {
		allowedHeaders = normalizedHeaderNames(egressauth.SimpleReplacementRuleHeaderNames(rules))
	}
	if len(allowedHeaders) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "egress auth request headers are unavailable")
	}
	headers := make(map[string]string, len(allowedHeaders))
	if len(rules) > 0 {
		for _, rule := range rules {
			name := normalizeHTTPHeaderName(rule.HeaderName)
			if name == "" || !headerNameAllowed(allowedHeaders, name) {
				continue
			}
			value, ok := runtimeEgressHeaderValueForRule(request, material, rule)
			if !ok {
				return nil, status.Error(codes.FailedPrecondition, "egress auth replacement failed")
			}
			headers[name] = value
		}
	} else {
		for _, name := range allowedHeaders {
			value, ok := runtimeEgressHeaderValue(request, material, name)
			if !ok {
				return nil, status.Error(codes.FailedPrecondition, "egress auth replacement failed")
			}
			headers[name] = value
		}
	}
	if len(headers) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "egress auth replacement failed")
	}
	return &authv1.ResolveEgressRequestHeadersResponse{
		Headers:       requestHeaderMutationsFromMap(headers),
		RemoveHeaders: egressauth.InternalHeaders(),
	}, nil
}

func runtimeEgressHeaderValueForRule(request *authv1.ResolveEgressRequestHeadersRequest, material map[string]string, rule egressauth.SimpleReplacementRule) (string, bool) {
	rule = egressauth.NormalizeSimpleReplacementRule(rule)
	name := normalizeHTTPHeaderName(rule.HeaderName)
	if name == "" {
		return "", false
	}
	current := egressauth.Placeholder
	prefix := firstNonEmptyString(rule.HeaderValuePrefix, request.GetHeaderValuePrefix())
	if prefix != "" {
		current = strings.TrimSpace(prefix) + " " + egressauth.Placeholder
	}
	return replaceEgressAuthHeader(request, []egressauth.SimpleReplacementRule{rule}, material, name, current)
}

func headerNameAllowed(values []string, name string) bool {
	name = normalizeHTTPHeaderName(name)
	for _, value := range values {
		if normalizeHTTPHeaderName(value) == name {
			return true
		}
	}
	return false
}

func (s *Server) resolveEgressRuntimeMetadata(ctx context.Context, source *authv1.EgressRequestSource) (*managementv1.AgentRunRuntimeMetadata, error) {
	if source == nil {
		return nil, status.Error(codes.InvalidArgument, "egress auth runtime source is required")
	}
	if s.agentSessions == nil {
		return nil, status.Error(codes.Unavailable, "egress auth runtime context unavailable")
	}
	request, err := managementRuntimeContextRequest(source)
	if err != nil {
		return nil, err
	}
	response, err := s.agentSessions.ResolveAgentRunRuntimeContext(ctx, request)
	if err != nil {
		code := status.Code(err)
		if code == codes.OK {
			code = codes.Unavailable
		}
		return nil, status.Error(code, "egress auth runtime context lookup failed")
	}
	if response == nil {
		return nil, status.Error(codes.FailedPrecondition, "egress auth runtime metadata is unavailable")
	}
	metadata := response.GetMetadata()
	if metadata == nil {
		return nil, status.Error(codes.FailedPrecondition, "egress auth runtime metadata is unavailable")
	}
	return metadata, nil
}

func managementRuntimeContextRequest(source *authv1.EgressRequestSource) (*managementv1.ResolveAgentRunRuntimeContextRequest, error) {
	switch value := source.GetSource().(type) {
	case *authv1.EgressRequestSource_Pod:
		pod := value.Pod
		if pod == nil {
			return nil, status.Error(codes.InvalidArgument, "egress auth runtime pod source is required")
		}
		return &managementv1.ResolveAgentRunRuntimeContextRequest{
			Source: &managementv1.ResolveAgentRunRuntimeContextRequest_Pod{Pod: &managementv1.AgentRunPodRef{
				Namespace: strings.TrimSpace(pod.GetNamespace()),
				Name:      strings.TrimSpace(pod.GetName()),
				Uid:       strings.TrimSpace(pod.GetUid()),
				Ip:        strings.TrimSpace(pod.GetIp()),
			}},
		}, nil
	case *authv1.EgressRequestSource_RunId:
		runID := strings.TrimSpace(value.RunId)
		if runID == "" {
			return nil, status.Error(codes.InvalidArgument, "egress auth runtime run_id is required")
		}
		return &managementv1.ResolveAgentRunRuntimeContextRequest{
			Source: &managementv1.ResolveAgentRunRuntimeContextRequest_RunId{RunId: runID},
		}, nil
	case *authv1.EgressRequestSource_WorkloadId:
		workloadID := strings.TrimSpace(value.WorkloadId)
		if workloadID == "" {
			return nil, status.Error(codes.InvalidArgument, "egress auth runtime workload_id is required")
		}
		return &managementv1.ResolveAgentRunRuntimeContextRequest{
			Source: &managementv1.ResolveAgentRunRuntimeContextRequest_WorkloadId{WorkloadId: workloadID},
		}, nil
	default:
		return nil, status.Error(codes.InvalidArgument, "egress auth runtime source is required")
	}
}

func applyEgressRuntimeMetadata(request *authv1.ResolveEgressRequestHeadersRequest, metadata *managementv1.AgentRunRuntimeMetadata) (*authv1.ResolveEgressRequestHeadersResponse, error) {
	if request == nil || metadata == nil {
		return nil, status.Error(codes.FailedPrecondition, "egress auth runtime metadata is unavailable")
	}
	request.CredentialId = strings.TrimSpace(metadata.GetCredentialId())
	request.AdapterId = ""
	request.SimpleReplacementRules = runtimeHeaderReplacementRulesToProto(metadata.GetRequestHeaderReplacementRules())
	if request.GetCredentialId() == "" {
		return skippedEgressRequestAuthResponse(), nil
	}
	if prefix := strings.TrimSpace(metadata.GetHeaderValuePrefix()); prefix != "" {
		request.HeaderValuePrefix = prefix
	} else {
		request.HeaderValuePrefix = ""
	}
	if names := runtimeHeaderReplacementRuleNames(metadata.GetRequestHeaderReplacementRules()); len(names) > 0 {
		request.AllowedHeaderNames = names
	} else if names := normalizedHeaderNames(metadata.GetRequestHeaderNames()); len(names) > 0 {
		request.AllowedHeaderNames = names
	} else {
		return skippedEgressRequestAuthResponse(), nil
	}
	if !matchesEgressTarget(request.GetTargetHost(), request.GetTargetPath(), metadata) {
		return skippedEgressRequestAuthResponse(), nil
	}
	return nil, nil
}

func applyEgressRuntimeResponseMetadata(request *authv1.ResolveEgressResponseHeadersRequest, metadata *managementv1.AgentRunRuntimeMetadata) (*authv1.ResolveEgressResponseHeadersResponse, error) {
	if request == nil || metadata == nil {
		return nil, status.Error(codes.FailedPrecondition, "egress auth runtime metadata is unavailable")
	}
	request.CredentialId = strings.TrimSpace(metadata.GetCredentialId())
	request.AdapterId = ""
	request.SimpleReplacementRules = runtimeHeaderReplacementRulesToProto(metadata.GetResponseHeaderReplacementRules())
	request.AllowedHeaderNames = runtimeHeaderReplacementRuleNames(metadata.GetResponseHeaderReplacementRules())
	if request.GetCredentialId() == "" {
		return skippedEgressResponseAuthResponse(), nil
	}
	if len(request.GetAllowedHeaderNames()) == 0 {
		return skippedEgressResponseAuthResponse(), nil
	}
	if !matchesEgressTarget(request.GetTargetHost(), request.GetTargetPath(), metadata) {
		return skippedEgressResponseAuthResponse(), nil
	}
	return nil, nil
}

func (s *Server) applyEgressProviderSurfaceBinding(ctx context.Context, request *authv1.ResolveEgressRequestHeadersRequest) error {
	credentialID, err := s.resolveEgressProviderSurfaceCredential(ctx, request.GetSourcePrincipal(), request.GetProviderSurfaceBindingId(), request.GetTargetHost(), request.GetAdapterId())
	if err != nil {
		return err
	}
	request.CredentialId = credentialID
	return nil
}

func (s *Server) applyEgressProviderSurfaceBindingForResponse(ctx context.Context, request *authv1.ResolveEgressResponseHeadersRequest) error {
	credentialID, err := s.resolveEgressProviderSurfaceCredential(ctx, request.GetSourcePrincipal(), request.GetProviderSurfaceBindingId(), request.GetTargetHost(), request.GetAdapterId())
	if err != nil {
		return err
	}
	request.CredentialId = credentialID
	return nil
}

func (s *Server) resolveEgressProviderSurfaceCredential(ctx context.Context, sourcePrincipal string, providerSurfaceBindingID string, targetHost string, adapterID string) (string, error) {
	providerSurfaceBindingID = strings.TrimSpace(providerSurfaceBindingID)
	if providerSurfaceBindingID == "" {
		return "", status.Error(codes.InvalidArgument, "egress auth provider surface binding id is required")
	}
	if !s.trustsEgressControlPlanePrincipal(sourcePrincipal) {
		return "", status.Error(codes.PermissionDenied, "egress auth source principal is not allowed")
	}
	if s == nil || s.providers == nil {
		return "", status.Error(codes.Unavailable, "egress auth provider binding lookup unavailable")
	}
	projection, err := providers.FindSurfaceBindingProjection(ctx, s.providers, providerSurfaceBindingID)
	if err != nil {
		return "", grpcError(err)
	}
	if projection == nil || projection.Surface == nil {
		return "", status.Error(codes.NotFound, "egress auth provider surface binding not found")
	}
	if !matchesProviderSurfaceTarget(targetHost, projection.Surface) {
		return "", status.Error(codes.PermissionDenied, "egress auth target does not match provider surface")
	}
	if usesProviderObservabilityCredential(adapterID) {
		if credentialID := provideridentity.ObservabilityCredentialID(projection.Provider.GetProviderId()); credentialID != "" {
			return credentialID, nil
		}
	}
	credentialID := strings.TrimSpace(projection.Surface.GetProviderCredentialRef().GetProviderCredentialId())
	if credentialID == "" {
		return "", status.Error(codes.FailedPrecondition, "egress auth provider surface binding has no credential")
	}
	return credentialID, nil
}

func usesProviderObservabilityCredential(adapterID string) bool {
	switch strings.TrimSpace(adapterID) {
	case egressauth.AuthAdapterBearerSessionID, egressauth.AuthAdapterGoogleAIStudioSessionID, egressauth.AuthAdapterSessionCookieID:
		return true
	default:
		return false
	}
}

func (s *Server) trustsEgressControlPlanePrincipal(sourcePrincipal string) bool {
	identity, ok := parseIstioSpiffePrincipal(sourcePrincipal)
	if !ok {
		return false
	}
	if s == nil || strings.TrimSpace(s.namespace) == "" || identity.namespace != strings.TrimSpace(s.namespace) {
		return false
	}
	switch identity.serviceAccount {
	case "platform-model-service", "platform-provider-service":
		return true
	default:
		return false
	}
}

type istioSpiffePrincipal struct {
	trustDomain    string
	namespace      string
	serviceAccount string
}

func parseIstioSpiffePrincipal(value string) (istioSpiffePrincipal, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "spiffe://") {
		return istioSpiffePrincipal{}, false
	}
	trimmed := strings.TrimPrefix(value, "spiffe://")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 5 || strings.TrimSpace(parts[0]) == "" {
		return istioSpiffePrincipal{}, false
	}
	out := istioSpiffePrincipal{trustDomain: strings.TrimSpace(parts[0])}
	for index := 1; index+1 < len(parts); index++ {
		switch parts[index] {
		case "ns":
			out.namespace = strings.TrimSpace(parts[index+1])
		case "sa":
			out.serviceAccount = strings.TrimSpace(parts[index+1])
		}
	}
	if out.namespace == "" || out.serviceAccount == "" {
		return istioSpiffePrincipal{}, false
	}
	return out, true
}

func matchesProviderSurfaceTarget(targetHost string, surface *providerv1.ProviderSurfaceBinding) bool {
	if surface == nil {
		return false
	}
	runtime := surface.GetRuntime()
	if runtime == nil {
		return false
	}
	baseURL := strings.TrimSpace(providerv1.RuntimeBaseURL(runtime))
	if baseURL == "" {
		return true
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed == nil {
		return false
	}
	return matchesEgressTargetHost(targetHost, []string{parsed.Host})
}

func matchesEgressTarget(targetHost string, targetPath string, metadata *managementv1.AgentRunRuntimeMetadata) bool {
	hosts := normalizedHosts(metadata.GetTargetHosts())
	if len(hosts) == 0 {
		return false
	}
	if !matchesEgressTargetHost(targetHost, hosts) {
		return false
	}
	paths := normalizedPathPrefixes(metadata.GetTargetPathPrefixes())
	return len(paths) == 0 || matchesEgressTargetPath(targetPath, paths)
}

func skippedEgressRequestAuthResponse() *authv1.ResolveEgressRequestHeadersResponse {
	return &authv1.ResolveEgressRequestHeadersResponse{
		Skipped:       true,
		RemoveHeaders: egressauth.InternalHeaders(),
	}
}

func skippedEgressResponseAuthResponse() *authv1.ResolveEgressResponseHeadersResponse {
	return &authv1.ResolveEgressResponseHeadersResponse{
		Skipped:       true,
		RemoveHeaders: egressauth.InternalHeaders(),
	}
}

func runtimeEgressHeaderValue(request *authv1.ResolveEgressRequestHeadersRequest, material map[string]string, name string) (string, bool) {
	name = normalizeHTTPHeaderName(name)
	if name == "" {
		return "", false
	}
	token, ok := runtimeMaterialByKey(material, strings.ReplaceAll(name, "-", "_"))
	if !ok {
		return "", false
	}
	prefix := strings.TrimSpace(request.GetHeaderValuePrefix())
	if prefix == "" {
		return token, true
	}
	return prefix + " " + token, true
}

func runtimeMaterialByKey(material map[string]string, key string) (string, bool) {
	key = normalizeRuntimeMaterialKey(key)
	for currentKey, value := range material {
		if normalizeRuntimeMaterialKey(currentKey) == key {
			value = strings.TrimSpace(value)
			if value != "" {
				return value, true
			}
		}
	}
	return "", false
}

func normalizeRuntimeMaterialKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.NewReplacer("-", "_", ".", "_").Replace(value)
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func replaceEgressAuthHeader(request *authv1.ResolveEgressRequestHeadersRequest, simpleRules []egressauth.SimpleReplacementRule, material map[string]string, name string, current string) (string, bool) {
	input := egressauth.ReplacementInput{
		AdapterID:         strings.TrimSpace(request.GetAdapterId()),
		HeaderName:        name,
		HeaderValuePrefix: strings.TrimSpace(request.GetHeaderValuePrefix()),
		CurrentValue:      current,
		Origin:            strings.TrimSpace(request.GetOrigin()),
		RequestHeaders:    request.GetRequestHeaders(),
		Material:          material,
		Now:               time.Now().UTC(),
	}
	if strings.TrimSpace(request.GetAdapterId()) == egressauth.AuthAdapterGoogleAIStudioSessionID {
		return googleaistudio.ReplaceHeader(input)
	}
	return egressauth.ReplaceSimpleHeader(input, simpleRules...)
}

func resolveEgressResponseHeaders(request *authv1.ResolveEgressResponseHeadersRequest, material map[string]string) (*authv1.ResolveEgressResponseHeadersResponse, error) {
	allowedHeaders := headerNameSet(request.GetAllowedHeaderNames())
	simpleRules := protoSimpleReplacementRules(request.GetSimpleReplacementRules())
	items := request.GetHeaders()
	if len(items) == 0 {
		items = headerReplacementItemsFromMap(request.GetResponseHeaders(), request.GetAllowedHeaderNames())
	}
	headers := make([]*authv1.EgressHeaderMutation, 0, len(items))
	for _, item := range items {
		name := normalizeHTTPHeaderName(item.GetName())
		current := strings.TrimSpace(item.GetCurrentValue())
		if len(allowedHeaders) > 0 {
			if _, ok := allowedHeaders[name]; !ok {
				continue
			}
		}
		if name == "" || current == "" {
			continue
		}
		next, ok := replaceEgressAuthResponseHeader(request, simpleRules, material, name, current)
		if ok {
			headers = append(headers, responseHeaderMutation(name, next))
		}
	}
	if len(headers) == 0 {
		return skippedEgressResponseAuthResponse(), nil
	}
	return &authv1.ResolveEgressResponseHeadersResponse{
		Headers:       headers,
		RemoveHeaders: headerMutationNames(headers),
	}, nil
}

func requestHeaderMutationsFromMap(headers map[string]string) []*authv1.EgressHeaderMutation {
	if len(headers) == 0 {
		return nil
	}
	normalized := make(map[string]string, len(headers))
	for name, value := range headers {
		name = normalizeHTTPHeaderName(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			continue
		}
		normalized[name] = value
	}
	names := make([]string, 0, len(normalized))
	for name := range normalized {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]*authv1.EgressHeaderMutation, 0, len(names))
	for _, name := range names {
		out = append(out, requestHeaderMutation(name, normalized[name]))
	}
	return out
}

func requestHeaderMutation(name string, value string) *authv1.EgressHeaderMutation {
	return egressHeaderMutation(name, value, authv1.EgressHeaderAppendAction_EGRESS_HEADER_APPEND_ACTION_OVERWRITE_IF_EXISTS_OR_ADD)
}

func responseHeaderMutation(name string, value string) *authv1.EgressHeaderMutation {
	action := authv1.EgressHeaderAppendAction_EGRESS_HEADER_APPEND_ACTION_OVERWRITE_IF_EXISTS_OR_ADD
	if normalizeHTTPHeaderName(name) == egressauth.HTTPHeaderSetCookie {
		action = authv1.EgressHeaderAppendAction_EGRESS_HEADER_APPEND_ACTION_APPEND_IF_EXISTS_OR_ADD
	}
	return egressHeaderMutation(name, value, action)
}

func egressHeaderMutation(name string, value string, action authv1.EgressHeaderAppendAction) *authv1.EgressHeaderMutation {
	name = normalizeHTTPHeaderName(name)
	value = strings.TrimSpace(value)
	if name == "" || value == "" {
		return nil
	}
	return &authv1.EgressHeaderMutation{
		Name:         name,
		Value:        value,
		AppendAction: action,
	}
}

func headerMutationNames(headers []*authv1.EgressHeaderMutation) []string {
	if len(headers) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(headers))
	for _, header := range headers {
		if header == nil {
			continue
		}
		name := normalizeHTTPHeaderName(header.GetName())
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func replaceEgressAuthResponseHeader(request *authv1.ResolveEgressResponseHeadersRequest, simpleRules []egressauth.SimpleReplacementRule, material map[string]string, name string, current string) (string, bool) {
	name = normalizeHTTPHeaderName(name)
	current = strings.TrimSpace(current)
	if name == "" || current == "" || len(material) == 0 {
		return "", false
	}
	replacements := responseHeaderReplacementPairs(simpleRules, material, name, strings.TrimSpace(request.GetHeaderValuePrefix()))
	if len(replacements) == 0 {
		return "", false
	}
	next := current
	replaced := false
	for _, pair := range replacements {
		if pair.secret == "" || pair.placeholder == "" || !strings.Contains(next, pair.secret) {
			continue
		}
		next = strings.ReplaceAll(next, pair.secret, pair.placeholder)
		replaced = true
	}
	if !replaced {
		return "", false
	}
	return next, true
}

type responseHeaderReplacementPair struct {
	secret      string
	placeholder string
}

func responseHeaderReplacementPairs(simpleRules []egressauth.SimpleReplacementRule, material map[string]string, name string, prefix string) []responseHeaderReplacementPair {
	name = normalizeHTTPHeaderName(name)
	var out []responseHeaderReplacementPair
	for _, rule := range simpleRules {
		normalized := egressauth.NormalizeSimpleReplacementRule(rule)
		if normalizeHTTPHeaderName(normalized.HeaderName) != name {
			continue
		}
		out = append(out, responseHeaderReplacementPairsForRule(normalized, material, name, prefix)...)
	}
	return out
}

func responseHeaderReplacementPairsForRule(rule egressauth.SimpleReplacementRule, material map[string]string, name string, prefix string) []responseHeaderReplacementPair {
	rule = egressauth.NormalizeSimpleReplacementRule(rule)
	token := ""
	if key := strings.TrimSpace(rule.MaterialKey); key != "" {
		if value, ok := runtimeMaterialByKey(material, key); ok {
			token = value
		}
	}
	if token == "" {
		return nil
	}
	template := strings.TrimSpace(rule.Template)
	if template != "" && strings.Contains(template, egressauth.Placeholder) {
		return []responseHeaderReplacementPair{{
			secret:      strings.ReplaceAll(template, egressauth.Placeholder, token),
			placeholder: template,
		}, {
			secret:      token,
			placeholder: egressauth.Placeholder,
		}}
	}
	rulePrefix := firstNonEmptyString(rule.HeaderValuePrefix, prefix)
	if rulePrefix != "" {
		return []responseHeaderReplacementPair{{
			secret:      strings.TrimSpace(rulePrefix) + " " + token,
			placeholder: strings.TrimSpace(rulePrefix) + " " + egressauth.Placeholder,
		}, {
			secret:      token,
			placeholder: egressauth.Placeholder,
		}}
	}
	return []responseHeaderReplacementPair{{secret: token, placeholder: egressauth.Placeholder}}
}

func materialFromResolvedCredential(credential *credentialv1.ResolvedCredential) map[string]string {
	if credential == nil {
		return nil
	}
	material := map[string]string{}
	if apiKey := credential.GetApiKey(); apiKey != nil {
		setResolvedMaterial(material, egressauth.MaterialKeyAPIKey, apiKey.GetApiKey())
	}
	if oauth := credential.GetOauth(); oauth != nil {
		setResolvedMaterial(material, egressauth.MaterialKeyAccessToken, oauth.GetAccessToken())
		setResolvedMaterial(material, "token", oauth.GetAccessToken())
		setResolvedMaterial(material, "token_type", oauth.GetTokenType())
		setResolvedMaterial(material, "refresh_token", oauth.GetRefreshToken())
		setResolvedMaterial(material, "id_token", oauth.GetIdToken())
	}
	if session := credential.GetSession(); session != nil {
		for key, value := range session.GetValues() {
			setResolvedMaterial(material, key, value)
		}
	}
	if len(material) == 0 {
		return nil
	}
	return material
}

func setResolvedMaterial(material map[string]string, key string, value string) {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return
	}
	material[key] = value
}

func httpHeaderMutationsFromProto(headers []*authv1.EgressHeaderMutation) []egressAuthHeaderMutation {
	if len(headers) == 0 {
		return nil
	}
	out := make([]egressAuthHeaderMutation, 0, len(headers))
	for _, header := range headers {
		if header == nil {
			continue
		}
		name := normalizeHTTPHeaderName(header.GetName())
		value := strings.TrimSpace(header.GetValue())
		if name == "" || value == "" {
			continue
		}
		out = append(out, egressAuthHeaderMutation{
			Name:         name,
			Value:        value,
			AppendAction: header.GetAppendAction().String(),
		})
	}
	return out
}

func httpEgressAuthRequestToProto(request egressAuthHeaderReplacementRequest) *authv1.ResolveEgressRequestHeadersRequest {
	headers := make([]*authv1.EgressHeaderReplacementItem, 0, len(request.Headers))
	for _, item := range request.Headers {
		headers = append(headers, &authv1.EgressHeaderReplacementItem{
			Name:         item.Name,
			CurrentValue: item.CurrentValue,
		})
	}
	return &authv1.ResolveEgressRequestHeadersRequest{
		CredentialId:           request.CredentialID,
		AdapterId:              request.AdapterID,
		TargetHost:             request.TargetHost,
		TargetPath:             request.TargetPath,
		HeaderValuePrefix:      request.HeaderValuePrefix,
		Origin:                 request.Origin,
		RequestHeaders:         request.RequestHeaders,
		SimpleReplacementRules: egressSimpleRulesToProto(request.SimpleReplacementRules),
		Headers:                headers,
	}
}

func httpEgressAuthResponseRequestToProto(request egressAuthResponseHeaderReplacementRequest) *authv1.ResolveEgressResponseHeadersRequest {
	headers := make([]*authv1.EgressHeaderReplacementItem, 0, len(request.Headers))
	for _, item := range request.Headers {
		headers = append(headers, &authv1.EgressHeaderReplacementItem{
			Name:         item.Name,
			CurrentValue: item.CurrentValue,
		})
	}
	return &authv1.ResolveEgressResponseHeadersRequest{
		CredentialId:           request.CredentialID,
		AdapterId:              request.AdapterID,
		TargetHost:             request.TargetHost,
		TargetPath:             request.TargetPath,
		HeaderValuePrefix:      request.HeaderValuePrefix,
		Origin:                 request.Origin,
		StatusCode:             request.StatusCode,
		RequestHeaders:         request.RequestHeaders,
		ResponseHeaders:        request.ResponseHeaders,
		SimpleReplacementRules: egressSimpleRulesToProto(request.SimpleReplacementRules),
		Headers:                headers,
	}
}

func egressSimpleRulesToProto(rules []egressauth.SimpleReplacementRule) []*authv1.EgressSimpleReplacementRule {
	out := make([]*authv1.EgressSimpleReplacementRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, &authv1.EgressSimpleReplacementRule{
			Mode:              rule.Mode,
			HeaderName:        rule.HeaderName,
			MaterialKey:       rule.MaterialKey,
			HeaderValuePrefix: rule.HeaderValuePrefix,
			Template:          rule.Template,
		})
	}
	return out
}

func protoSimpleReplacementRules(rules []*authv1.EgressSimpleReplacementRule) []egressauth.SimpleReplacementRule {
	out := make([]egressauth.SimpleReplacementRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		out = append(out, egressauth.SimpleReplacementRule{
			Mode:              rule.GetMode(),
			HeaderName:        rule.GetHeaderName(),
			MaterialKey:       rule.GetMaterialKey(),
			HeaderValuePrefix: rule.GetHeaderValuePrefix(),
			Template:          rule.GetTemplate(),
		})
	}
	return out
}

func runtimeHeaderReplacementRulesToProto(rules []*managementv1.AgentRunRuntimeHeaderReplacementRule) []*authv1.EgressSimpleReplacementRule {
	out := make([]*authv1.EgressSimpleReplacementRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		out = append(out, &authv1.EgressSimpleReplacementRule{
			Mode:              rule.GetMode(),
			HeaderName:        rule.GetHeaderName(),
			MaterialKey:       rule.GetMaterialKey(),
			HeaderValuePrefix: rule.GetHeaderValuePrefix(),
			Template:          rule.GetTemplate(),
		})
	}
	return out
}

func runtimeHeaderReplacementRuleNames(rules []*managementv1.AgentRunRuntimeHeaderReplacementRule) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		name := normalizeHTTPHeaderName(rule.GetHeaderName())
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func headerNameSet(names []string) map[string]struct{} {
	if len(names) == 0 {
		return nil
	}
	out := map[string]struct{}{}
	for _, name := range names {
		name = normalizeHTTPHeaderName(name)
		if name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

func normalizedHeaderNames(names []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = normalizeHTTPHeaderName(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func headerReplacementItemsFromMap(headers map[string]string, names []string) []*authv1.EgressHeaderReplacementItem {
	if len(headers) == 0 {
		return nil
	}
	allowed := headerNameSet(names)
	items := make([]*authv1.EgressHeaderReplacementItem, 0, len(headers))
	for name, value := range headers {
		name = normalizeHTTPHeaderName(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[name]; !ok {
				continue
			}
		}
		items = append(items, &authv1.EgressHeaderReplacementItem{Name: name, CurrentValue: value})
	}
	return items
}

func normalizedHosts(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		host := normalizeTargetHost(value)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func matchesEgressTargetHost(value string, allowed []string) bool {
	host := normalizeTargetHost(value)
	if host == "" {
		return false
	}
	for _, candidate := range allowed {
		if host == normalizeTargetHost(candidate) {
			return true
		}
	}
	return false
}

func normalizeTargetHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimSuffix(value, ".")
	if strings.HasPrefix(value, "[") {
		if index := strings.Index(value, "]"); index > 0 {
			return value[1:index]
		}
	}
	if index := strings.LastIndex(value, ":"); index > 0 && !strings.Contains(value[:index], ":") {
		value = value[:index]
	}
	return strings.Trim(value, "[]")
}

func normalizedPathPrefixes(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		prefix := normalizeTargetPath(value)
		if prefix == "" {
			continue
		}
		if prefix != "/" {
			prefix = strings.TrimRight(prefix, "/")
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out
}

func matchesEgressTargetPath(value string, prefixes []string) bool {
	path := normalizeTargetPath(value)
	if path == "" {
		return false
	}
	for _, prefix := range prefixes {
		prefix = normalizeTargetPath(prefix)
		if prefix == "/" || path == prefix || strings.HasPrefix(path, strings.TrimRight(prefix, "/")+"/") || strings.HasPrefix(path, strings.TrimRight(prefix, "/")+":") {
			return true
		}
	}
	return false
}

func normalizeTargetPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if index := strings.IndexAny(value, "?#"); index >= 0 {
		value = value[:index]
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	if value == "" {
		return "/"
	}
	return value
}

func normalizeHTTPHeaderName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func httpStatusForEgressAuthError(err error) int {
	switch status.Code(err) {
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadGateway
	}
}

func writeEgressAuthError(w http.ResponseWriter, status int, message string) {
	if strings.TrimSpace(message) == "" {
		message = http.StatusText(status)
	}
	writeEgressAuthJSON(w, status, egressAuthHeaderReplacementResponse{Error: message})
}

func writeEgressAuthJSON(w http.ResponseWriter, status int, response egressAuthHeaderReplacementResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		_, _ = fmt.Fprintln(w, `{"error":"egress auth response encoding failed"}`)
	}
}
