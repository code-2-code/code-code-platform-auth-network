package support

import (
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
)

func externalAccessSetFromRuleSet(ruleSet externalRuleSetConfig) *egressv1.ExternalAccessSet {
	accessSet := &egressv1.ExternalAccessSet{
		AccessSetId:  ruleSet.RuleSetID,
		DisplayName:  ruleSet.DisplayName,
		OwnerService: ruleSet.OwnerService,
		PolicyId:     ruleSet.PolicyID,
	}
	for _, rule := range ruleSet.Rules {
		accessSet.ExternalRules = append(accessSet.ExternalRules, &egressv1.ExternalRule{
			ExternalRuleId: ruleSet.RuleSetID + "." + rule.RuleID,
			DestinationId:  rule.DestinationID,
			DisplayName:    rule.DisplayName,
			HostMatch:      hostMatch(rule),
			Port:           rule.Port,
			Protocol:       egressProtocol(rule.Protocol),
			Resolution:     egressResolution(rule.Resolution),
			EgressPath:     egressPath(rule.ProxyEndpointID),
		})
		accessSet.ServiceRules = append(accessSet.ServiceRules, &egressv1.ServiceRule{
			ServiceRuleId:         rule.DestinationID + ".services",
			DestinationId:         rule.DestinationID,
			SourceServiceAccounts: sourceServiceAccounts(ruleSet.SourceServiceAccounts, rule.SourceServiceAccounts),
		})
	}
	for _, rule := range ruleSet.HTTPInspectionRules {
		accessSet.HttpInspectionRules = append(accessSet.HttpInspectionRules, &egressv1.HttpInspectionRule{
			InspectionRuleId:   rule.InspectionRuleID,
			DisplayName:        rule.DisplayName,
			DestinationId:      rule.DestinationID,
			Matches:            httpRouteMatches(rule.Matches),
			RequestHeaders:     httpHeaderPolicy(rule.RequestHeaders),
			ResponseHeaders:    httpHeaderPolicy(rule.ResponseHeaders),
			AuthPolicyId:       rule.AuthPolicyID,
			DynamicHeaderAuthz: rule.DynamicHeaderAuthz,
		})
	}
	return accessSet
}

func egressPath(proxyEndpointID string) *egressv1.EgressPath {
	proxyEndpointID = strings.TrimSpace(proxyEndpointID)
	if proxyEndpointID == "" {
		return nil
	}
	return &egressv1.EgressPath{
		Mode:            egressv1.EgressPathMode_EGRESS_PATH_MODE_PROXY,
		ProxyEndpointId: proxyEndpointID,
	}
}

func hostMatch(rule externalRuleSetRule) *egressv1.HostMatch {
	if rule.HostWildcard != "" {
		return &egressv1.HostMatch{Kind: &egressv1.HostMatch_HostWildcard{HostWildcard: rule.HostWildcard}}
	}
	return &egressv1.HostMatch{Kind: &egressv1.HostMatch_HostExact{HostExact: rule.HostExact}}
}

func httpRouteMatches(matches []externalRuleSetMatch) []*egressv1.HttpRouteMatch {
	out := make([]*egressv1.HttpRouteMatch, 0, len(matches))
	for _, match := range matches {
		out = append(out, &egressv1.HttpRouteMatch{
			PathPrefixes: match.PathPrefixes,
			Methods:      match.Methods,
		})
	}
	return out
}

func httpHeaderPolicy(policy externalRuleSetHeaderPolicy) *egressv1.HttpHeaderPolicy {
	if len(policy.Add) == 0 && len(policy.Set) == 0 && len(policy.Remove) == 0 {
		return nil
	}
	return &egressv1.HttpHeaderPolicy{
		Add:    httpHeaderValues(policy.Add),
		Set:    httpHeaderValues(policy.Set),
		Remove: policy.Remove,
	}
}

func httpHeaderValues(values []externalRuleSetHeaderValue) []*egressv1.HttpHeaderValue {
	out := make([]*egressv1.HttpHeaderValue, 0, len(values))
	for _, value := range values {
		out = append(out, &egressv1.HttpHeaderValue{Name: value.Name, Value: value.Value})
	}
	return out
}

func egressProtocol(value string) egressv1.EgressProtocol {
	switch strings.ToLower(value) {
	case "http":
		return egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTP
	case "https":
		return egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS
	case "tcp":
		return egressv1.EgressProtocol_EGRESS_PROTOCOL_TCP
	default:
		return egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS
	}
}

func egressResolution(value string) egressv1.EgressResolution {
	switch strings.ToLower(value) {
	case "dynamic-dns":
		return egressv1.EgressResolution_EGRESS_RESOLUTION_DYNAMIC_DNS
	case "none":
		return egressv1.EgressResolution_EGRESS_RESOLUTION_NONE
	default:
		return egressv1.EgressResolution_EGRESS_RESOLUTION_DNS
	}
}
