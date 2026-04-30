package egresspolicies

import (
	"fmt"
	"net/textproto"
	"slices"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/validation"
)

func normalizeHTTPInspectionRules(rules []*egressv1.HttpInspectionRule) ([]*egressv1.HttpInspectionRule, error) {
	seen := map[string]struct{}{}
	out := make([]*egressv1.HttpInspectionRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		normalized := proto.Clone(rule).(*egressv1.HttpInspectionRule)
		normalized.InspectionRuleId = strings.TrimSpace(normalized.GetInspectionRuleId())
		if normalized.InspectionRuleId == "" {
			return nil, fmt.Errorf("http inspection rule id is empty")
		}
		if _, ok := seen[normalized.GetInspectionRuleId()]; ok {
			return nil, fmt.Errorf("duplicate http inspection rule %q", normalized.GetInspectionRuleId())
		}
		seen[normalized.GetInspectionRuleId()] = struct{}{}
		normalized.DisplayName = displayNameOr(normalized.GetDisplayName(), normalized.GetInspectionRuleId())
		normalized.DestinationId = strings.TrimSpace(normalized.GetDestinationId())
		if normalized.DestinationId == "" {
			return nil, fmt.Errorf("http inspection rule %q destination id is empty", normalized.GetInspectionRuleId())
		}
		matches, err := normalizeHTTPRouteMatches(normalized.GetMatches())
		if err != nil {
			return nil, fmt.Errorf("http inspection rule %q: %w", normalized.GetInspectionRuleId(), err)
		}
		requestHeaders, err := normalizeHeaderPolicy(normalized.GetRequestHeaders())
		if err != nil {
			return nil, fmt.Errorf("http inspection rule %q request headers: %w", normalized.GetInspectionRuleId(), err)
		}
		responseHeaders, err := normalizeHeaderPolicy(normalized.GetResponseHeaders())
		if err != nil {
			return nil, fmt.Errorf("http inspection rule %q response headers: %w", normalized.GetInspectionRuleId(), err)
		}
		normalized.Matches = matches
		normalized.RequestHeaders = requestHeaders
		normalized.ResponseHeaders = responseHeaders
		normalized.AuthPolicyId = strings.TrimSpace(normalized.GetAuthPolicyId())
		out = append(out, normalized)
	}
	slices.SortFunc(out, func(a, b *egressv1.HttpInspectionRule) int {
		return strings.Compare(a.GetInspectionRuleId(), b.GetInspectionRuleId())
	})
	return out, nil
}

func normalizeEgressPath(path *egressv1.EgressPath) (*egressv1.EgressPath, error) {
	if path == nil || path.GetMode() == egressv1.EgressPathMode_EGRESS_PATH_MODE_UNSPECIFIED || path.GetMode() == egressv1.EgressPathMode_EGRESS_PATH_MODE_DIRECT {
		return nil, nil
	}
	if path.GetMode() != egressv1.EgressPathMode_EGRESS_PATH_MODE_PROXY {
		return nil, fmt.Errorf("mode %s is not supported", path.GetMode().String())
	}
	proxyEndpointID := strings.TrimSpace(path.GetProxyEndpointId())
	if proxyEndpointID == "" {
		return nil, fmt.Errorf("proxy_endpoint_id is required")
	}
	return &egressv1.EgressPath{
		Mode:            egressv1.EgressPathMode_EGRESS_PATH_MODE_PROXY,
		ProxyEndpointId: proxyEndpointID,
	}, nil
}

func normalizeHTTPRouteMatches(matches []*egressv1.HttpRouteMatch) ([]*egressv1.HttpRouteMatch, error) {
	out := make([]*egressv1.HttpRouteMatch, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}
		normalized := proto.Clone(match).(*egressv1.HttpRouteMatch)
		pathPrefixes, err := normalizePathPrefixes(normalized.GetPathPrefixes())
		if err != nil {
			return nil, err
		}
		methods, err := normalizeHTTPMethods(normalized.GetMethods())
		if err != nil {
			return nil, err
		}
		if len(pathPrefixes) == 0 && len(methods) == 0 {
			continue
		}
		normalized.PathPrefixes = pathPrefixes
		normalized.Methods = methods
		out = append(out, normalized)
	}
	return out, nil
}

func normalizePathPrefixes(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.HasPrefix(value, "/") {
			return nil, fmt.Errorf("path prefix %q must start with /", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out, nil
}

func normalizeHTTPMethods(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if errs := validation.IsHTTPHeaderName(value); len(errs) > 0 {
			return nil, fmt.Errorf("method %q is invalid: %s", value, strings.Join(errs, "; "))
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out, nil
}

func normalizeHeaderPolicy(policy *egressv1.HttpHeaderPolicy) (*egressv1.HttpHeaderPolicy, error) {
	if policy == nil {
		return nil, nil
	}
	add, err := normalizeHeaderValues(policy.GetAdd(), false)
	if err != nil {
		return nil, err
	}
	set, err := normalizeHeaderValues(policy.GetSet(), true)
	if err != nil {
		return nil, err
	}
	remove, err := normalizeHeaderNames(policy.GetRemove())
	if err != nil {
		return nil, err
	}
	if len(add) == 0 && len(set) == 0 && len(remove) == 0 {
		return nil, nil
	}
	return &egressv1.HttpHeaderPolicy{Add: add, Set: set, Remove: remove}, nil
}

func normalizeHeaderValues(values []*egressv1.HttpHeaderValue, uniqueName bool) ([]*egressv1.HttpHeaderValue, error) {
	seenNames := map[string]struct{}{}
	seenValues := map[string]struct{}{}
	out := make([]*egressv1.HttpHeaderValue, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		name, err := normalizeHeaderName(value.GetName())
		if err != nil {
			return nil, err
		}
		if name == "" {
			continue
		}
		if uniqueName {
			if _, ok := seenNames[strings.ToLower(name)]; ok {
				return nil, fmt.Errorf("duplicate header %q", name)
			}
			seenNames[strings.ToLower(name)] = struct{}{}
		}
		key := strings.ToLower(name) + "\x00" + value.GetValue()
		if _, ok := seenValues[key]; ok {
			continue
		}
		seenValues[key] = struct{}{}
		out = append(out, &egressv1.HttpHeaderValue{Name: name, Value: value.GetValue()})
	}
	slices.SortFunc(out, func(a, b *egressv1.HttpHeaderValue) int {
		if a.GetName() != b.GetName() {
			return strings.Compare(strings.ToLower(a.GetName()), strings.ToLower(b.GetName()))
		}
		return strings.Compare(a.GetValue(), b.GetValue())
	})
	return out, nil
}

func normalizeHeaderNames(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		name, err := normalizeHeaderName(value)
		if err != nil {
			return nil, err
		}
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	slices.SortFunc(out, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	})
	return out, nil
}

func normalizeHeaderName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if errs := validation.IsHTTPHeaderName(value); len(errs) > 0 {
		return "", fmt.Errorf("header %q is invalid: %s", value, strings.Join(errs, "; "))
	}
	return textproto.CanonicalMIMEHeaderKey(value), nil
}
