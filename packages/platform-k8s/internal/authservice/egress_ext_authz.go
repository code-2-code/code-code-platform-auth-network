package authservice

import (
	"context"
	"encoding/json"
	"strings"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	"code-code.internal/platform-k8s/internal/egressauth"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyauthv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

const egressExtAuthzDeniedBody = "egress auth denied"

// EgressExtAuthzServer adapts Envoy's ext_authz check API to the auth-owned
// header replacement policy engine.
type EgressExtAuthzServer struct {
	envoyauthv3.UnimplementedAuthorizationServer

	auth *Server
}

func NewEgressExtAuthzServer(auth *Server) *EgressExtAuthzServer {
	return &EgressExtAuthzServer{auth: auth}
}

func (s *EgressExtAuthzServer) Check(ctx context.Context, request *envoyauthv3.CheckRequest) (*envoyauthv3.CheckResponse, error) {
	if s == nil || s.auth == nil {
		return deniedExtAuthzResponse(codes.Unavailable, typev3.StatusCode_BadGateway), nil
	}
	resolveRequest, ok := extAuthzResolveRequest(request, s.auth.runtimeNamespace)
	if !ok {
		return allowedExtAuthzResponse(nil, nil), nil
	}
	response, err := s.auth.ResolveEgressRequestHeaders(ctx, resolveRequest)
	if err != nil {
		code := grpcstatus.Code(err)
		if code == codes.OK {
			code = codes.Unknown
		}
		return deniedExtAuthzResponse(code, statusCodeForExtAuthzError(code)), nil
	}
	if response.GetSkipped() {
		return allowedExtAuthzResponse(nil, response.GetRemoveHeaders()), nil
	}
	if strings.TrimSpace(response.GetError()) != "" {
		return deniedExtAuthzResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden), nil
	}
	return allowedExtAuthzResponse(response.GetHeaders(), response.GetRemoveHeaders()), nil
}

func extAuthzResolveRequest(request *envoyauthv3.CheckRequest, runtimeNamespace string) (*authv1.ResolveEgressRequestHeadersRequest, bool) {
	if request == nil || request.GetAttributes() == nil {
		return nil, false
	}
	attributes := request.GetAttributes()
	http := attributes.GetRequest().GetHttp()
	if http == nil {
		return nil, false
	}
	headers := normalizedExtAuthzHeaders(http.GetHeaders())
	targetHost := firstNonEmptyString(http.GetHost(), headers[":authority"], headers["host"])
	targetPath := firstNonEmptyString(http.GetPath(), headers[":path"])
	if strings.TrimSpace(targetHost) == "" || strings.TrimSpace(targetPath) == "" {
		return nil, false
	}
	if request, ok := extAuthzProviderSurfaceResolveRequest(attributes.GetSource(), headers, targetHost, targetPath); ok {
		return request, true
	}
	source := extAuthzRuntimeSource(attributes.GetSource(), runtimeNamespace)
	if source == nil {
		return nil, false
	}
	return &authv1.ResolveEgressRequestHeadersRequest{
		TargetHost:      targetHost,
		TargetPath:      targetPath,
		SourcePrincipal: strings.TrimSpace(attributes.GetSource().GetPrincipal()),
		RequestHeaders:  headers,
		RuntimeSource:   source,
	}, true
}

func extAuthzProviderSurfaceResolveRequest(
	peer *envoyauthv3.AttributeContext_Peer,
	headers map[string]string,
	targetHost string,
	targetPath string,
) (*authv1.ResolveEgressRequestHeadersRequest, bool) {
	providerSurfaceBindingID := extAuthzHeaderValue(headers, egressauth.HeaderProviderSurfaceBindingID)
	if providerSurfaceBindingID == "" {
		return nil, false
	}
	allowedHeaderNames := extAuthzHeaderList(headers, egressauth.HeaderRequestHeaderNames)
	rules := extAuthzSimpleReplacementRules(extAuthzHeaderValue(headers, egressauth.HeaderRequestHeaderRulesJSON))
	return &authv1.ResolveEgressRequestHeadersRequest{
		PolicyId:                 firstNonEmptyString(extAuthzHeaderValue(headers, egressauth.HeaderAuthPolicyID), extAuthzHeaderValue(headers, egressauth.HeaderEgressPolicyID)),
		AdapterId:                extAuthzHeaderValue(headers, egressauth.HeaderAuthAdapterID),
		TargetHost:               targetHost,
		TargetPath:               targetPath,
		HeaderValuePrefix:        extAuthzHeaderValue(headers, egressauth.HeaderHeaderValuePrefix),
		RequestHeaders:           headers,
		SimpleReplacementRules:   egressSimpleRulesToProto(rules),
		AllowedHeaderNames:       allowedHeaderNames,
		SourcePrincipal:          strings.TrimSpace(peer.GetPrincipal()),
		ProviderSurfaceBindingId: providerSurfaceBindingID,
		EgressPolicyId:           extAuthzHeaderValue(headers, egressauth.HeaderEgressPolicyID),
		AuthPolicyId:             extAuthzHeaderValue(headers, egressauth.HeaderAuthPolicyID),
	}, true
}

func extAuthzHeaderValue(headers map[string]string, name string) string {
	if len(headers) == 0 {
		return ""
	}
	return strings.TrimSpace(headers[normalizeHTTPHeaderName(name)])
}

func extAuthzHeaderList(headers map[string]string, name string) []string {
	raw := extAuthzHeaderValue(headers, name)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = normalizeHTTPHeaderName(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return normalizedHeaderNames(out)
}

func extAuthzSimpleReplacementRules(raw string) []egressauth.SimpleReplacementRule {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var rules []egressauth.SimpleReplacementRule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return nil
	}
	return rules
}

func extAuthzRuntimeSource(peer *envoyauthv3.AttributeContext_Peer, runtimeNamespace string) *authv1.EgressRequestSource {
	ip := extAuthzPeerIP(peer)
	if ip == "" {
		return nil
	}
	namespace := extAuthzPeerNamespace(peer.GetPrincipal())
	if runtimeNamespace = strings.TrimSpace(runtimeNamespace); runtimeNamespace != "" && namespace != runtimeNamespace {
		return nil
	}
	return &authv1.EgressRequestSource{Source: &authv1.EgressRequestSource_Pod{Pod: &authv1.EgressPodSource{
		Namespace: namespace,
		Ip:        ip,
	}}}
}

func extAuthzPeerIP(peer *envoyauthv3.AttributeContext_Peer) string {
	if peer == nil {
		return ""
	}
	socket := peer.GetAddress().GetSocketAddress()
	if socket == nil {
		return ""
	}
	return normalizeSourceAddress(socket.GetAddress())
}

func extAuthzPeerNamespace(principal string) string {
	principal = strings.TrimSpace(principal)
	if !strings.HasPrefix(principal, "spiffe://") {
		return ""
	}
	parts := strings.Split(principal, "/")
	for index := 0; index+3 < len(parts); index++ {
		if parts[index] == "ns" && parts[index+2] == "sa" {
			return strings.TrimSpace(parts[index+1])
		}
	}
	return ""
}

func normalizedExtAuthzHeaders(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		key = normalizeHTTPHeaderName(key)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(value)
	}
	return out
}

func allowedExtAuthzResponse(headers []*authv1.EgressHeaderMutation, removeHeaders []string) *envoyauthv3.CheckResponse {
	return &envoyauthv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &envoyauthv3.CheckResponse_OkResponse{OkResponse: &envoyauthv3.OkHttpResponse{
			Headers:         extAuthzHeaderOptions(headers),
			HeadersToRemove: normalizedExtAuthzHeaderNames(removeHeaders),
		}},
	}
}

func deniedExtAuthzResponse(code codes.Code, httpStatus typev3.StatusCode) *envoyauthv3.CheckResponse {
	return &envoyauthv3.CheckResponse{
		Status: &status.Status{Code: int32(code)},
		HttpResponse: &envoyauthv3.CheckResponse_DeniedResponse{DeniedResponse: &envoyauthv3.DeniedHttpResponse{
			Status: &typev3.HttpStatus{Code: httpStatus},
			Headers: extAuthzHeaderOptions(requestHeaderMutationsFromMap(map[string]string{
				"content-type": "text/plain; charset=utf-8",
			})),
			Body: egressExtAuthzDeniedBody,
		}},
	}
}

func statusCodeForExtAuthzError(code codes.Code) typev3.StatusCode {
	switch code {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.NotFound:
		return typev3.StatusCode_Forbidden
	case codes.Unavailable, codes.DeadlineExceeded:
		return typev3.StatusCode_BadGateway
	default:
		return typev3.StatusCode_BadGateway
	}
}

func extAuthzHeaderOptions(headers []*authv1.EgressHeaderMutation) []*corev3.HeaderValueOption {
	if len(headers) == 0 {
		return nil
	}
	out := make([]*corev3.HeaderValueOption, 0, len(headers))
	for _, header := range headers {
		if header == nil {
			continue
		}
		name := normalizeHTTPHeaderName(header.GetName())
		value := strings.TrimSpace(header.GetValue())
		if name == "" || value == "" {
			continue
		}
		out = append(out, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   name,
				Value: value,
			},
			AppendAction: extAuthzAppendAction(header.GetAppendAction()),
		})
	}
	return out
}

func extAuthzAppendAction(action authv1.EgressHeaderAppendAction) corev3.HeaderValueOption_HeaderAppendAction {
	switch action {
	case authv1.EgressHeaderAppendAction_EGRESS_HEADER_APPEND_ACTION_APPEND_IF_EXISTS_OR_ADD:
		return corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD
	case authv1.EgressHeaderAppendAction_EGRESS_HEADER_APPEND_ACTION_ADD_IF_ABSENT:
		return corev3.HeaderValueOption_ADD_IF_ABSENT
	default:
		return corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD
	}
}

func normalizedExtAuthzHeaderNames(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizeHTTPHeaderName(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeSourceAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
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
