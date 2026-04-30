package authservice

import (
	"context"
	"strings"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

func (s *Server) applyEgressRequestAuthPolicy(request *authv1.ResolveEgressRequestHeadersRequest) error {
	if strings.TrimSpace(request.GetCredentialId()) != "" {
		return nil
	}
	if hasRequestHeaderPolicy(request) {
		return nil
	}
	policy, err := s.resolveEgressRequestAuthPolicy(request)
	if err != nil || policy == nil {
		return err
	}
	request.CredentialId = firstNonEmptyString(request.GetCredentialId(), policy.GetCredentialId())
	request.AdapterId = firstNonEmptyString(request.GetAdapterId(), policy.GetAdapterId())
	request.HeaderValuePrefix = firstNonEmptyString(request.GetHeaderValuePrefix(), policy.GetHeaderValuePrefix())
	if len(request.GetAllowedHeaderNames()) == 0 {
		request.AllowedHeaderNames = append([]string(nil), policy.GetRequestHeaderNames()...)
	}
	if len(request.GetSimpleReplacementRules()) == 0 {
		request.SimpleReplacementRules = append([]*authv1.EgressSimpleReplacementRule(nil), policy.GetRequestReplacementRules()...)
	}
	return nil
}

func (s *Server) applyEgressResponseAuthPolicy(request *authv1.ResolveEgressResponseHeadersRequest) error {
	if strings.TrimSpace(request.GetCredentialId()) != "" {
		return nil
	}
	if hasResponseHeaderPolicy(request) {
		return nil
	}
	policy, err := s.resolveEgressResponseAuthPolicy(request)
	if err != nil || policy == nil {
		return err
	}
	request.CredentialId = firstNonEmptyString(request.GetCredentialId(), policy.GetCredentialId())
	request.AdapterId = firstNonEmptyString(request.GetAdapterId(), policy.GetAdapterId())
	request.HeaderValuePrefix = firstNonEmptyString(request.GetHeaderValuePrefix(), policy.GetHeaderValuePrefix())
	if len(request.GetAllowedHeaderNames()) == 0 {
		request.AllowedHeaderNames = append([]string(nil), policy.GetResponseHeaderNames()...)
	}
	if len(request.GetSimpleReplacementRules()) == 0 {
		request.SimpleReplacementRules = append([]*authv1.EgressSimpleReplacementRule(nil), policy.GetResponseReplacementRules()...)
	}
	return nil
}

func (s *Server) resolveEgressRequestAuthPolicy(request *authv1.ResolveEgressRequestHeadersRequest) (*authv1.GetEgressAuthPolicyResponse, error) {
	if policy, err := s.resolveExplicitEgressAuthPolicy(firstNonEmptyString(request.GetAuthPolicyId(), request.GetPolicyId())); err != nil || policy != nil {
		return policy, err
	}
	if s == nil || s.headerRewritePolicies == nil {
		return nil, status.Error(codes.Unavailable, "egress auth policy lookup unavailable")
	}
	policy, ok, err := s.headerRewritePolicies.ResolveRequestPolicy(request)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "egress auth policy match failed")
	}
	if !ok {
		return nil, nil
	}
	return policy, nil
}

func (s *Server) resolveEgressResponseAuthPolicy(request *authv1.ResolveEgressResponseHeadersRequest) (*authv1.GetEgressAuthPolicyResponse, error) {
	if policy, err := s.resolveExplicitEgressAuthPolicy(firstNonEmptyString(request.GetAuthPolicyId(), request.GetPolicyId())); err != nil || policy != nil {
		return policy, err
	}
	if s == nil || s.headerRewritePolicies == nil {
		return nil, status.Error(codes.Unavailable, "egress auth policy lookup unavailable")
	}
	policy, ok, err := s.headerRewritePolicies.ResolveResponsePolicy(request)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "egress auth policy match failed")
	}
	if !ok {
		return nil, nil
	}
	return policy, nil
}

func (s *Server) resolveExplicitEgressAuthPolicy(policyID string) (*authv1.GetEgressAuthPolicyResponse, error) {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, nil
	}
	if s == nil || s.headerRewritePolicies == nil {
		return nil, status.Error(codes.Unavailable, "egress auth policy lookup unavailable")
	}
	policy, ok := s.headerRewritePolicies.ResolvePolicyID(policyID)
	if !ok || policy == nil {
		return nil, status.Error(codes.NotFound, "egress auth policy not found")
	}
	return policy, nil
}

func hasRequestHeaderPolicy(request *authv1.ResolveEgressRequestHeadersRequest) bool {
	return strings.TrimSpace(request.GetAdapterId()) != "" ||
		strings.TrimSpace(request.GetHeaderValuePrefix()) != "" ||
		len(request.GetAllowedHeaderNames()) > 0 ||
		len(request.GetSimpleReplacementRules()) > 0
}

func hasResponseHeaderPolicy(request *authv1.ResolveEgressResponseHeadersRequest) bool {
	return strings.TrimSpace(request.GetAdapterId()) != "" ||
		strings.TrimSpace(request.GetHeaderValuePrefix()) != "" ||
		len(request.GetAllowedHeaderNames()) > 0 ||
		len(request.GetSimpleReplacementRules()) > 0
}
