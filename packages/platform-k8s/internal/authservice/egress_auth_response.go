package authservice

import (
	"strings"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	"code-code.internal/platform-k8s/internal/egressauth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func resolveEgressResponseHeaders(request *authv1.ResolveEgressResponseHeadersRequest, material map[string]string) (*authv1.ResolveEgressResponseHeadersResponse, error) {
	allowedHeaders := headerNameSet(request.GetAllowedHeaderNames())
	simpleRules := protoSimpleReplacementRules(request.GetSimpleReplacementRules())
	items := request.GetHeaders()
	if len(items) == 0 {
		items = headerReplacementItemsFromMap(request.GetResponseHeaders(), request.GetAllowedHeaderNames())
	}
	headers := make([]*authv1.EgressHeaderMutation, 0, len(items))
	removeHeaders := normalizedHeaderNames(egressauth.InternalHeaders())
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
		if name == egressauth.HTTPHeaderSetCookie {
			removeHeaders = appendUniqueHeaderName(removeHeaders, name)
		}
		next, ok := replaceEgressAuthResponseHeader(request, simpleRules, material, name, current)
		if ok {
			headers = append(headers, responseHeaderMutation(name, next))
		}
	}
	if len(headers) == 0 && len(removeHeaders) == len(egressauth.InternalHeaders()) {
		return skippedEgressResponseAuthResponse(), nil
	}
	removeHeaders = appendUniqueHeaderNames(removeHeaders, headerMutationNames(headers)...)
	return &authv1.ResolveEgressResponseHeadersResponse{
		Headers:       headers,
		RemoveHeaders: removeHeaders,
	}, nil
}

func appendUniqueHeaderNames(values []string, names ...string) []string {
	for _, name := range names {
		values = appendUniqueHeaderName(values, name)
	}
	return values
}

func appendUniqueHeaderName(values []string, name string) []string {
	name = normalizeHTTPHeaderName(name)
	if name == "" {
		return values
	}
	for _, value := range values {
		if normalizeHTTPHeaderName(value) == name {
			return values
		}
	}
	return append(values, name)
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
				return nil, egressAuthReplacementFailedHeaderError(name)
			}
			headers[name] = value
		}
	} else {
		for _, name := range allowedHeaders {
			value, ok := runtimeEgressHeaderValue(request, material, name)
			if !ok {
				return nil, egressAuthReplacementFailedHeaderError(name)
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

func egressAuthReplacementFailedHeaderError(name string) error {
	name = normalizeHTTPHeaderName(name)
	if name == "" {
		return status.Error(codes.FailedPrecondition, "egress auth replacement failed")
	}
	return status.Errorf(codes.FailedPrecondition, "egress auth replacement failed for header %q", name)
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
