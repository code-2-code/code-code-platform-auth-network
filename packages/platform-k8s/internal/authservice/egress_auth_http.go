package authservice

import (
	"context"
	"strings"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	"code-code.internal/platform-k8s/internal/egressauth"
	"code-code.internal/platform-k8s/internal/egressauth/adapters/googleaistudio"
	"code-code.internal/platform-k8s/internal/egressauth/adapters/mistraladmin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) ResolveEgressRequestHeaders(ctx context.Context, request *authv1.ResolveEgressRequestHeadersRequest) (*authv1.ResolveEgressRequestHeadersResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid egress auth replacement request")
	}
	request.CredentialId = strings.TrimSpace(request.GetCredentialId())
	request.TargetHost = strings.TrimSpace(request.GetTargetHost())
	request.TargetPath = strings.TrimSpace(request.GetTargetPath())
	request.TargetMethod = strings.TrimSpace(request.GetTargetMethod())
	request.SourcePrincipal = strings.TrimSpace(request.GetSourcePrincipal())
	request.PolicyId = strings.TrimSpace(request.GetPolicyId())
	request.EgressPolicyId = strings.TrimSpace(request.GetEgressPolicyId())
	request.AuthPolicyId = strings.TrimSpace(request.GetAuthPolicyId())
	runtimeRequest := request.GetRuntimeSource() != nil
	policyCandidate := request.GetPolicyId() != "" ||
		request.GetAuthPolicyId() != "" ||
		request.GetSourcePrincipal() != "" ||
		request.GetTargetHost() != ""
	if !runtimeRequest && request.GetCredentialId() == "" && len(request.GetHeaders()) == 0 && !policyCandidate {
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
	} else {
		if err := s.applyEgressRequestAuthPolicy(request); err != nil {
			return nil, err
		}
	}
	if request.GetCredentialId() == "" {
		if !runtimeRequest && len(request.GetHeaders()) == 0 && request.GetPolicyId() == "" && request.GetAuthPolicyId() == "" {
			return skippedEgressRequestAuthResponse(), nil
		}
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
	request.TargetMethod = strings.TrimSpace(request.GetTargetMethod())
	request.SourcePrincipal = strings.TrimSpace(request.GetSourcePrincipal())
	request.PolicyId = strings.TrimSpace(request.GetPolicyId())
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
	} else {
		if err := s.applyEgressResponseAuthPolicy(request); err != nil {
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
	if strings.TrimSpace(request.GetAdapterId()) == mistraladmin.AdapterID {
		return mistraladmin.ReplaceHeader(input)
	}
	return egressauth.ReplaceSimpleHeader(input, simpleRules...)
}
