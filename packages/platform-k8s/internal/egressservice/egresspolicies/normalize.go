package egresspolicies

import (
	"fmt"
	"net/netip"
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
	proxyEndpoints, err := normalizeProxyEndpoints(normalized.GetProxyEndpoints())
	if err != nil {
		return nil, fmt.Errorf("external access set %q: %w", normalized.GetAccessSetId(), err)
	}
	serviceRules, err := normalizeServiceRules(normalized.GetServiceRules())
	if err != nil {
		return nil, fmt.Errorf("external access set %q: %w", normalized.GetAccessSetId(), err)
	}
	httpInspectionRules, err := normalizeHTTPInspectionRules(normalized.GetHttpInspectionRules())
	if err != nil {
		return nil, fmt.Errorf("external access set %q: %w", normalized.GetAccessSetId(), err)
	}
	normalized.ExternalRules = externalRules
	normalized.ProxyEndpoints = proxyEndpoints
	normalized.ServiceRules = serviceRules
	normalized.HttpInspectionRules = httpInspectionRules
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
		egressPath, err := normalizeEgressPath(normalized.GetEgressPath())
		if err != nil {
			return nil, fmt.Errorf("external rule %q egress path: %w", normalized.GetExternalRuleId(), err)
		}
		if egressPath != nil && normalized.GetProtocol() != egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS {
			return nil, fmt.Errorf("external rule %q egress path is only supported for TLS passthrough destinations", normalized.GetExternalRuleId())
		}
		normalized.EgressPath = egressPath
		out = append(out, normalized)
	}
	slices.SortFunc(out, func(a, b *egressv1.ExternalRule) int {
		return strings.Compare(a.GetExternalRuleId(), b.GetExternalRuleId())
	})
	return out, nil
}

func normalizeProxyEndpoints(endpoints []*egressv1.ProxyEndpoint) ([]*egressv1.ProxyEndpoint, error) {
	seen := map[string]struct{}{}
	out := make([]*egressv1.ProxyEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint == nil {
			continue
		}
		normalized := proto.Clone(endpoint).(*egressv1.ProxyEndpoint)
		normalized.ProxyEndpointId = strings.TrimSpace(normalized.GetProxyEndpointId())
		if normalized.ProxyEndpointId == "" {
			return nil, fmt.Errorf("proxy endpoint id is empty")
		}
		if _, ok := seen[normalized.GetProxyEndpointId()]; ok {
			return nil, fmt.Errorf("duplicate proxy endpoint %q", normalized.GetProxyEndpointId())
		}
		seen[normalized.GetProxyEndpointId()] = struct{}{}
		normalized.DisplayName = displayNameOr(normalized.GetDisplayName(), normalized.GetProxyEndpointId())
		hostMatch, err := normalizeHostMatch(normalized.GetHostMatch())
		if err != nil {
			return nil, fmt.Errorf("proxy endpoint %q: %w", normalized.GetProxyEndpointId(), err)
		}
		if hostMatch.GetHostWildcard() != "" {
			return nil, fmt.Errorf("proxy endpoint %q host_wildcard is not supported", normalized.GetProxyEndpointId())
		}
		normalized.HostMatch = hostMatch
		if normalized.GetPort() <= 0 || normalized.GetPort() > 65535 {
			return nil, fmt.Errorf("proxy endpoint %q port must be between 1 and 65535", normalized.GetProxyEndpointId())
		}
		switch normalized.GetProtocol() {
		case egressv1.ProxyProtocol_PROXY_PROTOCOL_HTTP_CONNECT, egressv1.ProxyProtocol_PROXY_PROTOCOL_SOCKS5:
		default:
			return nil, fmt.Errorf("proxy endpoint %q protocol is unspecified or unsupported", normalized.GetProxyEndpointId())
		}
		if normalized.GetResolution() == egressv1.EgressResolution_EGRESS_RESOLUTION_UNSPECIFIED {
			return nil, fmt.Errorf("proxy endpoint %q resolution is unspecified", normalized.GetProxyEndpointId())
		}
		normalized.AddressCidr = strings.TrimSpace(normalized.GetAddressCidr())
		if normalized.GetAddressCidr() == "" {
			return nil, fmt.Errorf("proxy endpoint %q address_cidr is required for generated forwarder NetworkPolicy", normalized.GetProxyEndpointId())
		}
		prefix, err := netip.ParsePrefix(normalized.GetAddressCidr())
		if err != nil {
			return nil, fmt.Errorf("proxy endpoint %q address_cidr is invalid: %w", normalized.GetProxyEndpointId(), err)
		}
		if !prefix.IsSingleIP() {
			return nil, fmt.Errorf("proxy endpoint %q address_cidr must identify a single IP", normalized.GetProxyEndpointId())
		}
		out = append(out, normalized)
	}
	slices.SortFunc(out, func(a, b *egressv1.ProxyEndpoint) int {
		return strings.Compare(a.GetProxyEndpointId(), b.GetProxyEndpointId())
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
