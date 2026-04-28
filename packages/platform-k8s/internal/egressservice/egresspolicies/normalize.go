package egresspolicies

import (
	"fmt"
	"net/netip"
	"net/textproto"
	"slices"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/validation"
)

func normalizePolicy(policy *egressv1.EgressPolicy) (*egressv1.EgressPolicy, error) {
	if policy == nil {
		return defaultPolicy(), nil
	}
	normalized := proto.Clone(policy).(*egressv1.EgressPolicy)
	normalized.PolicyId = strings.TrimSpace(normalized.GetPolicyId())
	if normalized.PolicyId == "" {
		normalized.PolicyId = policyID
	}
	normalized.DisplayName = displayNameOr(normalized.GetDisplayName(), policyDisplayName)
	seen := map[string]struct{}{}
	accessSets := make([]*egressv1.ExternalAccessSet, 0, len(normalized.GetAccessSets()))
	for _, accessSet := range normalized.GetAccessSets() {
		normalizedSet, err := normalizeAccessSet(accessSet, normalized.GetPolicyId())
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalizedSet.GetAccessSetId()]; ok {
			return nil, fmt.Errorf("duplicate external access set %q", normalizedSet.GetAccessSetId())
		}
		seen[normalizedSet.GetAccessSetId()] = struct{}{}
		accessSets = append(accessSets, normalizedSet)
	}
	slices.SortFunc(accessSets, func(a, b *egressv1.ExternalAccessSet) int {
		return strings.Compare(a.GetAccessSetId(), b.GetAccessSetId())
	})
	normalized.AccessSets = accessSets
	return normalized, nil
}

func normalizeAccessSet(accessSet *egressv1.ExternalAccessSet, fallbackPolicyID string) (*egressv1.ExternalAccessSet, error) {
	if accessSet == nil {
		return nil, fmt.Errorf("external access set is nil")
	}
	normalized := proto.Clone(accessSet).(*egressv1.ExternalAccessSet)
	normalized.AccessSetId = strings.TrimSpace(normalized.GetAccessSetId())
	if normalized.AccessSetId == "" {
		return nil, fmt.Errorf("external access set id is empty")
	}
	normalized.DisplayName = displayNameOr(normalized.GetDisplayName(), normalized.GetAccessSetId())
	normalized.OwnerService = strings.TrimSpace(normalized.GetOwnerService())
	normalized.PolicyId = strings.TrimSpace(normalized.GetPolicyId())
	if normalized.PolicyId == "" {
		normalized.PolicyId = strings.TrimSpace(fallbackPolicyID)
	}
	if normalized.PolicyId == "" {
		normalized.PolicyId = policyID
	}

	externalRules, err := normalizeExternalRules(normalized.GetExternalRules())
	if err != nil {
		return nil, fmt.Errorf("external access set %q: %w", normalized.GetAccessSetId(), err)
	}
	serviceRules, err := normalizeServiceRules(normalized.GetServiceRules())
	if err != nil {
		return nil, fmt.Errorf("external access set %q: %w", normalized.GetAccessSetId(), err)
	}
	httpRoutes, err := normalizeHTTPRoutes(normalized.GetHttpRoutes())
	if err != nil {
		return nil, fmt.Errorf("external access set %q: %w", normalized.GetAccessSetId(), err)
	}
	normalized.ExternalRules = externalRules
	normalized.ServiceRules = serviceRules
	normalized.HttpRoutes = httpRoutes
	return normalized, nil
}

func normalizeExternalRules(rules []*egressv1.ExternalRule) ([]*egressv1.ExternalRule, error) {
	seen := map[string]struct{}{}
	out := make([]*egressv1.ExternalRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		normalized := proto.Clone(rule).(*egressv1.ExternalRule)
		normalized.ExternalRuleId = strings.TrimSpace(normalized.GetExternalRuleId())
		if normalized.ExternalRuleId == "" {
			return nil, fmt.Errorf("external rule id is empty")
		}
		if _, ok := seen[normalized.GetExternalRuleId()]; ok {
			return nil, fmt.Errorf("duplicate external rule %q", normalized.GetExternalRuleId())
		}
		seen[normalized.GetExternalRuleId()] = struct{}{}
		normalized.DestinationId = strings.TrimSpace(normalized.GetDestinationId())
		if normalized.DestinationId == "" {
			return nil, fmt.Errorf("external rule %q destination id is empty", normalized.GetExternalRuleId())
		}
		normalized.DisplayName = displayNameOr(normalized.GetDisplayName(), normalized.GetDestinationId())
		hostMatch, err := normalizeHostMatch(normalized.GetHostMatch())
		if err != nil {
			return nil, fmt.Errorf("external rule %q: %w", normalized.GetExternalRuleId(), err)
		}
		if hostMatch.GetHostWildcard() != "" {
			return nil, fmt.Errorf("external rule %q host_wildcard is not supported by the Ambient waypoint egress path; use exact hosts or route broad domains through a corporate proxy destination", normalized.GetExternalRuleId())
		}
		normalized.HostMatch = hostMatch
		if normalized.GetPort() <= 0 || normalized.GetPort() > 65535 {
			return nil, fmt.Errorf("external rule %q port must be between 1 and 65535", normalized.GetExternalRuleId())
		}
		if normalized.GetProtocol() == egressv1.EgressProtocol_EGRESS_PROTOCOL_UNSPECIFIED {
			return nil, fmt.Errorf("external rule %q protocol is unspecified", normalized.GetExternalRuleId())
		}
		if normalized.GetResolution() == egressv1.EgressResolution_EGRESS_RESOLUTION_UNSPECIFIED {
			return nil, fmt.Errorf("external rule %q resolution is unspecified", normalized.GetExternalRuleId())
		}
		normalized.AddressCidr = strings.TrimSpace(normalized.GetAddressCidr())
		if normalized.GetAddressCidr() != "" {
			if _, err := netip.ParsePrefix(normalized.GetAddressCidr()); err != nil {
				return nil, fmt.Errorf("external rule %q address_cidr is invalid: %w", normalized.GetExternalRuleId(), err)
			}
		}
		out = append(out, normalized)
	}
	slices.SortFunc(out, func(a, b *egressv1.ExternalRule) int {
		return strings.Compare(a.GetExternalRuleId(), b.GetExternalRuleId())
	})
	return out, nil
}

func normalizeServiceRules(rules []*egressv1.ServiceRule) ([]*egressv1.ServiceRule, error) {
	seen := map[string]struct{}{}
	out := make([]*egressv1.ServiceRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		normalized := proto.Clone(rule).(*egressv1.ServiceRule)
		normalized.ServiceRuleId = strings.TrimSpace(normalized.GetServiceRuleId())
		if normalized.ServiceRuleId == "" {
			normalized.ServiceRuleId = strings.TrimSpace(normalized.GetDestinationId()) + ".services"
		}
		if normalized.ServiceRuleId == ".services" {
			return nil, fmt.Errorf("service rule id is empty")
		}
		if _, ok := seen[normalized.GetServiceRuleId()]; ok {
			return nil, fmt.Errorf("duplicate service rule %q", normalized.GetServiceRuleId())
		}
		seen[normalized.GetServiceRuleId()] = struct{}{}
		normalized.DestinationId = strings.TrimSpace(normalized.GetDestinationId())
		if normalized.DestinationId == "" {
			return nil, fmt.Errorf("service rule %q destination id is empty", normalized.GetServiceRuleId())
		}
		accounts, err := normalizeServiceAccounts(normalized.GetSourceServiceAccounts())
		if err != nil {
			return nil, fmt.Errorf("service rule %q: %w", normalized.GetServiceRuleId(), err)
		}
		normalized.SourceServiceAccounts = accounts
		out = append(out, normalized)
	}
	slices.SortFunc(out, func(a, b *egressv1.ServiceRule) int {
		return strings.Compare(a.GetServiceRuleId(), b.GetServiceRuleId())
	})
	return out, nil
}

func normalizeHTTPRoutes(routes []*egressv1.HttpEgressRoute) ([]*egressv1.HttpEgressRoute, error) {
	seen := map[string]struct{}{}
	out := make([]*egressv1.HttpEgressRoute, 0, len(routes))
	for _, route := range routes {
		if route == nil {
			continue
		}
		normalized := proto.Clone(route).(*egressv1.HttpEgressRoute)
		normalized.RouteId = strings.TrimSpace(normalized.GetRouteId())
		if normalized.RouteId == "" {
			return nil, fmt.Errorf("http route id is empty")
		}
		if _, ok := seen[normalized.GetRouteId()]; ok {
			return nil, fmt.Errorf("duplicate http route %q", normalized.GetRouteId())
		}
		seen[normalized.GetRouteId()] = struct{}{}
		normalized.DisplayName = displayNameOr(normalized.GetDisplayName(), normalized.GetRouteId())
		normalized.DestinationId = strings.TrimSpace(normalized.GetDestinationId())
		if normalized.DestinationId == "" {
			return nil, fmt.Errorf("http route %q destination id is empty", normalized.GetRouteId())
		}
		matches, err := normalizeHTTPRouteMatches(normalized.GetMatches())
		if err != nil {
			return nil, fmt.Errorf("http route %q: %w", normalized.GetRouteId(), err)
		}
		requestHeaders, err := normalizeHeaderPolicy(normalized.GetRequestHeaders())
		if err != nil {
			return nil, fmt.Errorf("http route %q request headers: %w", normalized.GetRouteId(), err)
		}
		responseHeaders, err := normalizeHeaderPolicy(normalized.GetResponseHeaders())
		if err != nil {
			return nil, fmt.Errorf("http route %q response headers: %w", normalized.GetRouteId(), err)
		}
		normalized.Matches = matches
		normalized.RequestHeaders = requestHeaders
		normalized.ResponseHeaders = responseHeaders
		normalized.AuthPolicyId = strings.TrimSpace(normalized.GetAuthPolicyId())
		out = append(out, normalized)
	}
	slices.SortFunc(out, func(a, b *egressv1.HttpEgressRoute) int {
		return strings.Compare(a.GetRouteId(), b.GetRouteId())
	})
	return out, nil
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

func normalizeHostMatch(match *egressv1.HostMatch) (*egressv1.HostMatch, error) {
	if match == nil {
		return nil, fmt.Errorf("host match is empty")
	}
	if host := strings.TrimSpace(strings.ToLower(match.GetHostExact())); host != "" {
		if strings.Contains(host, "*") {
			return nil, fmt.Errorf("host_exact must not contain wildcard")
		}
		return &egressv1.HostMatch{Kind: &egressv1.HostMatch_HostExact{HostExact: host}}, nil
	}
	if host := strings.TrimSpace(strings.ToLower(match.GetHostWildcard())); host != "" {
		host = strings.TrimPrefix(host, "*.")
		if host == "" || strings.Contains(host, "*") {
			return nil, fmt.Errorf("host_wildcard must be a single DNS wildcard suffix")
		}
		return &egressv1.HostMatch{Kind: &egressv1.HostMatch_HostWildcard{HostWildcard: "*." + host}}, nil
	}
	return nil, fmt.Errorf("host match is empty")
}

func normalizeServiceAccounts(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		namespace, name, ok := strings.Cut(value, "/")
		if !ok || strings.TrimSpace(namespace) == "" || strings.TrimSpace(name) == "" || strings.Contains(name, "/") {
			return nil, fmt.Errorf("source service account %q must use namespace/name", value)
		}
		namespace = strings.TrimSpace(namespace)
		name = strings.TrimSpace(name)
		if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
			return nil, fmt.Errorf("source service account namespace %q is invalid: %s", namespace, strings.Join(errs, "; "))
		}
		if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
			return nil, fmt.Errorf("source service account name %q is invalid: %s", name, strings.Join(errs, "; "))
		}
		value = namespace + "/" + name
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out, nil
}

func defaultPolicy() *egressv1.EgressPolicy {
	return &egressv1.EgressPolicy{
		PolicyId:    policyID,
		DisplayName: policyDisplayName,
	}
}
