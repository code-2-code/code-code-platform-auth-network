package egresspolicies

import (
	"fmt"
	"slices"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
	"code-code.internal/platform-k8s/internal/egressauthpolicy"
	"google.golang.org/protobuf/proto"
)

type desiredState struct {
	destinations        []*externalDestination
	proxyEndpoints      []*proxyEndpoint
	httpInspectionRules []*httpInspectionRule
}

type externalDestination struct {
	destinationID   string
	displayName     string
	host            string
	addressCidr     string
	port            int32
	protocol        egressv1.EgressProtocol
	resolution      egressv1.EgressResolution
	proxyEndpointID string
	proxyEndpoint   *proxyEndpoint
	ownerServices   []string
	accessSetIDs    []string
	serviceAccounts []string
	serviceEntry    *serviceEntryGroup
}

type httpInspectionRule struct {
	resourceID         string
	inspectionRuleID   string
	displayName        string
	destination        *externalDestination
	matches            []*httpRouteMatch
	requestHeaders     headerPolicy
	responseHeaders    headerPolicy
	authPolicyID       string
	authProviderName   string
	dynamicHeaderAuthz bool
	ownerServices      []string
	accessSetIDs       []string
}

type proxyEndpoint struct {
	proxyEndpointID string
	displayName     string
	host            string
	addressCidr     string
	port            int32
	protocol        egressv1.ProxyProtocol
	resolution      egressv1.EgressResolution
	ownerServices   []string
	accessSetIDs    []string
}

type httpRouteMatch struct {
	pathPrefixes []string
	methods      []string
}

type headerPolicy struct {
	add    []headerValue
	set    []headerValue
	remove []string
}

type headerValue struct {
	name  string
	value string
}

func desiredStateFromPolicy(policy *egressv1.EgressPolicy) (desiredState, error) {
	destinations := map[string]*externalDestination{}
	proxyEndpoints := map[string]*proxyEndpoint{}
	for _, accessSet := range policy.GetAccessSets() {
		for _, rule := range accessSet.GetExternalRules() {
			destination, err := destinationFromRule(accessSet, rule)
			if err != nil {
				return desiredState{}, err
			}
			existing, ok := destinations[destination.destinationID]
			if !ok {
				destinations[destination.destinationID] = destination
				continue
			}
			if !sameExternalDestination(existing, destination) {
				return desiredState{}, fmt.Errorf("external destination %q has conflicting declarations", destination.destinationID)
			}
			existing.ownerServices = mergeValues(existing.ownerServices, destination.ownerServices)
			existing.accessSetIDs = mergeValues(existing.accessSetIDs, destination.accessSetIDs)
		}
		for _, endpoint := range accessSet.GetProxyEndpoints() {
			proxy, err := proxyEndpointFromProto(accessSet, endpoint)
			if err != nil {
				return desiredState{}, err
			}
			existing, ok := proxyEndpoints[proxy.proxyEndpointID]
			if !ok {
				proxyEndpoints[proxy.proxyEndpointID] = proxy
				continue
			}
			if !sameProxyEndpoint(existing, proxy) {
				return desiredState{}, fmt.Errorf("proxy endpoint %q has conflicting declarations", proxy.proxyEndpointID)
			}
			existing.ownerServices = mergeValues(existing.ownerServices, proxy.ownerServices)
			existing.accessSetIDs = mergeValues(existing.accessSetIDs, proxy.accessSetIDs)
		}
	}
	if err := resolveDestinationProxyEndpoints(destinations, proxyEndpoints); err != nil {
		return desiredState{}, err
	}
	for _, accessSet := range policy.GetAccessSets() {
		for _, rule := range accessSet.GetServiceRules() {
			destination, ok := destinations[rule.GetDestinationId()]
			if !ok {
				return desiredState{}, fmt.Errorf("service rule %q references unknown destination %q", rule.GetServiceRuleId(), rule.GetDestinationId())
			}
			destination.serviceAccounts = mergeValues(destination.serviceAccounts, rule.GetSourceServiceAccounts())
		}
	}
	httpInspectionRules := make([]*httpInspectionRule, 0)
	for _, accessSet := range policy.GetAccessSets() {
		for _, rule := range accessSet.GetHttpInspectionRules() {
			inspectionRule, err := httpInspectionRuleFromProto(accessSet, rule, destinations)
			if err != nil {
				return desiredState{}, err
			}
			httpInspectionRules = append(httpInspectionRules, inspectionRule)
		}
	}
	out := make([]*externalDestination, 0, len(destinations))
	for _, destination := range destinations {
		out = append(out, destination)
	}
	proxies := make([]*proxyEndpoint, 0, len(proxyEndpoints))
	for _, proxy := range proxyEndpoints {
		proxies = append(proxies, proxy)
	}
	slices.SortFunc(out, func(a, b *externalDestination) int {
		return strings.Compare(a.destinationID, b.destinationID)
	})
	slices.SortFunc(proxies, func(a, b *proxyEndpoint) int {
		return strings.Compare(a.proxyEndpointID, b.proxyEndpointID)
	})
	slices.SortFunc(httpInspectionRules, func(a, b *httpInspectionRule) int {
		return strings.Compare(a.resourceID, b.resourceID)
	})
	return desiredState{destinations: out, proxyEndpoints: proxies, httpInspectionRules: httpInspectionRules}, nil
}

func destinationFromRule(accessSet *egressv1.ExternalAccessSet, rule *egressv1.ExternalRule) (*externalDestination, error) {
	host := rule.GetHostMatch().GetHostExact()
	if host == "" {
		host = rule.GetHostMatch().GetHostWildcard()
	}
	if host == "" {
		return nil, fmt.Errorf("external rule %q host is empty", rule.GetExternalRuleId())
	}
	proxyEndpointID, err := proxyEndpointIDFromEgressPath(rule.GetEgressPath())
	if err != nil {
		return nil, fmt.Errorf("external rule %q egress path: %w", rule.GetExternalRuleId(), err)
	}
	return &externalDestination{
		destinationID:   rule.GetDestinationId(),
		displayName:     displayNameOr(rule.GetDisplayName(), rule.GetDestinationId()),
		host:            host,
		addressCidr:     rule.GetAddressCidr(),
		port:            rule.GetPort(),
		protocol:        rule.GetProtocol(),
		resolution:      rule.GetResolution(),
		proxyEndpointID: proxyEndpointID,
		ownerServices:   valueIfNotEmpty(accessSet.GetOwnerService()),
		accessSetIDs:    []string{accessSet.GetAccessSetId()},
	}, nil
}

func sameExternalDestination(a, b *externalDestination) bool {
	return a.host == b.host &&
		a.addressCidr == b.addressCidr &&
		a.port == b.port &&
		a.protocol == b.protocol &&
		a.resolution == b.resolution &&
		a.proxyEndpointID == b.proxyEndpointID
}

func resolveDestinationProxyEndpoints(destinations map[string]*externalDestination, proxyEndpoints map[string]*proxyEndpoint) error {
	for _, destination := range destinations {
		if destination.proxyEndpointID == "" {
			continue
		}
		if strings.HasPrefix(destination.host, "*.") {
			return fmt.Errorf("external destination %q uses proxy egress path on wildcard host; managed TLS egress routes require an exact SNI host", destination.destinationID)
		}
		if destination.protocol != egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS {
			return fmt.Errorf("external destination %q uses proxy egress path with %s protocol; destination-level proxy routing currently requires TLS passthrough", destination.destinationID, protocolString(destination.protocol))
		}
		proxy, ok := proxyEndpoints[destination.proxyEndpointID]
		if !ok {
			return fmt.Errorf("external destination %q references unknown proxy endpoint %q", destination.destinationID, destination.proxyEndpointID)
		}
		destination.proxyEndpoint = proxy
	}
	return nil
}

func proxyEndpointFromProto(accessSet *egressv1.ExternalAccessSet, endpoint *egressv1.ProxyEndpoint) (*proxyEndpoint, error) {
	host := endpoint.GetHostMatch().GetHostExact()
	if host == "" {
		host = endpoint.GetHostMatch().GetHostWildcard()
	}
	if host == "" {
		return nil, fmt.Errorf("proxy endpoint %q host is empty", endpoint.GetProxyEndpointId())
	}
	return &proxyEndpoint{
		proxyEndpointID: endpoint.GetProxyEndpointId(),
		displayName:     displayNameOr(endpoint.GetDisplayName(), endpoint.GetProxyEndpointId()),
		host:            host,
		addressCidr:     endpoint.GetAddressCidr(),
		port:            endpoint.GetPort(),
		protocol:        endpoint.GetProtocol(),
		resolution:      endpoint.GetResolution(),
		ownerServices:   valueIfNotEmpty(accessSet.GetOwnerService()),
		accessSetIDs:    []string{accessSet.GetAccessSetId()},
	}, nil
}

func sameProxyEndpoint(a, b *proxyEndpoint) bool {
	return a.host == b.host &&
		a.addressCidr == b.addressCidr &&
		a.port == b.port &&
		a.protocol == b.protocol &&
		a.resolution == b.resolution
}

func httpInspectionRuleFromProto(accessSet *egressv1.ExternalAccessSet, rule *egressv1.HttpInspectionRule, destinations map[string]*externalDestination) (*httpInspectionRule, error) {
	destination, ok := destinations[rule.GetDestinationId()]
	if !ok {
		return nil, fmt.Errorf("http inspection rule %q references unknown destination %q", rule.GetInspectionRuleId(), rule.GetDestinationId())
	}
	if strings.HasPrefix(destination.host, "*.") {
		return nil, fmt.Errorf("http inspection rule %q references wildcard destination %q; L7 header policy requires an exact host", rule.GetInspectionRuleId(), destination.destinationID)
	}
	if destination.protocol != egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS {
		return nil, fmt.Errorf("http inspection rule %q references %s destination %q; L7 egress requires an HTTPS destination with TLS origination", rule.GetInspectionRuleId(), protocolString(destination.protocol), destination.destinationID)
	}
	authPolicyID := strings.TrimSpace(rule.GetAuthPolicyId())
	authProviderName, err := authProviderNameForInspectionRule(authPolicyID, rule.GetDynamicHeaderAuthz())
	if err != nil {
		return nil, fmt.Errorf("http inspection rule %q: %w", rule.GetInspectionRuleId(), err)
	}
	return &httpInspectionRule{
		resourceID:         accessSet.GetAccessSetId() + "." + rule.GetInspectionRuleId(),
		inspectionRuleID:   rule.GetInspectionRuleId(),
		displayName:        displayNameOr(rule.GetDisplayName(), rule.GetInspectionRuleId()),
		destination:        destination,
		matches:            httpRouteMatchesFromProto(rule.GetMatches()),
		requestHeaders:     headerPolicyFromProto(rule.GetRequestHeaders()),
		responseHeaders:    headerPolicyFromProto(rule.GetResponseHeaders()),
		authPolicyID:       authPolicyID,
		authProviderName:   authProviderName,
		dynamicHeaderAuthz: rule.GetDynamicHeaderAuthz(),
		ownerServices:      valueIfNotEmpty(accessSet.GetOwnerService()),
		accessSetIDs:       []string{accessSet.GetAccessSetId()},
	}, nil
}

func proxyEndpointIDFromEgressPath(egressPath *egressv1.EgressPath) (string, error) {
	if egressPath == nil || egressPath.GetMode() == egressv1.EgressPathMode_EGRESS_PATH_MODE_UNSPECIFIED || egressPath.GetMode() == egressv1.EgressPathMode_EGRESS_PATH_MODE_DIRECT {
		return "", nil
	}
	if egressPath.GetMode() != egressv1.EgressPathMode_EGRESS_PATH_MODE_PROXY {
		return "", fmt.Errorf("egress path mode %s is not supported", egressPath.GetMode().String())
	}
	proxyID := strings.TrimSpace(egressPath.GetProxyEndpointId())
	if proxyID == "" {
		return "", fmt.Errorf("proxy egress path requires proxy_endpoint_id")
	}
	return proxyID, nil
}

func authProviderNameForInspectionRule(authPolicyID string, dynamicHeaderAuthz bool) (string, error) {
	if !dynamicHeaderAuthz || strings.TrimSpace(authPolicyID) == "" {
		return "", nil
	}
	catalog, err := egressauthpolicy.DefaultCatalog()
	if err != nil {
		return "", fmt.Errorf("load egress auth policy catalog: %w", err)
	}
	policy, ok := catalog.ResolvePolicyID(authPolicyID)
	if !ok {
		return "", fmt.Errorf("unknown auth policy %q", strings.TrimSpace(authPolicyID))
	}
	providerName := strings.TrimSpace(policy.GetExtensionProviderName())
	if providerName == "" {
		return "", fmt.Errorf("auth policy %q has no Istio extension provider", strings.TrimSpace(authPolicyID))
	}
	return providerName, nil
}

func httpRouteMatchesFromProto(matches []*egressv1.HttpRouteMatch) []*httpRouteMatch {
	out := make([]*httpRouteMatch, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}
		out = append(out, &httpRouteMatch{
			pathPrefixes: mergeValues(nil, match.GetPathPrefixes()),
			methods:      mergeValues(nil, match.GetMethods()),
		})
	}
	return out
}

func headerPolicyFromProto(policy *egressv1.HttpHeaderPolicy) headerPolicy {
	if policy == nil {
		return headerPolicy{}
	}
	return headerPolicy{
		add:    headerValuesFromProto(policy.GetAdd()),
		set:    headerValuesFromProto(policy.GetSet()),
		remove: mergeValues(nil, policy.GetRemove()),
	}
}

func headerValuesFromProto(values []*egressv1.HttpHeaderValue) []headerValue {
	out := make([]headerValue, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		out = append(out, headerValue{name: strings.TrimSpace(value.GetName()), value: value.GetValue()})
	}
	return out
}

func mergeValues(base []string, additions []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(base)+len(additions))
	for _, value := range append(append([]string{}, base...), additions...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func valueIfNotEmpty(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return []string{value}
}

type accessSetDiff struct {
	addedExternalRule      int32
	updatedExternalRule    int32
	removedExternalRule    int32
	unchangedExternalRule  int32
	addedProxyEndpoint     int32
	updatedProxyEndpoint   int32
	removedProxyEndpoint   int32
	unchangedProxyEndpoint int32
}

func diffAccessSet(before, after *egressv1.ExternalAccessSet) accessSetDiff {
	beforeRules := accessSetItemMap(before)
	afterRules := accessSetItemMap(after)
	var diff accessSetDiff
	for id, next := range afterRules {
		prev, ok := beforeRules[id]
		if !ok {
			diff.increment(id, "added")
			continue
		}
		if proto.Equal(prev, next) {
			diff.increment(id, "unchanged")
		} else {
			diff.increment(id, "updated")
		}
	}
	for id := range beforeRules {
		if _, ok := afterRules[id]; !ok {
			diff.increment(id, "removed")
		}
	}
	return diff
}

func (d *accessSetDiff) increment(id string, operation string) {
	switch {
	case strings.HasPrefix(id, "external:"):
		switch operation {
		case "added":
			d.addedExternalRule++
		case "updated":
			d.updatedExternalRule++
		case "removed":
			d.removedExternalRule++
		case "unchanged":
			d.unchangedExternalRule++
		}
	case strings.HasPrefix(id, "proxy:"):
		switch operation {
		case "added":
			d.addedProxyEndpoint++
		case "updated":
			d.updatedProxyEndpoint++
		case "removed":
			d.removedProxyEndpoint++
		case "unchanged":
			d.unchangedProxyEndpoint++
		}
	}
}

func accessSetItemMap(accessSet *egressv1.ExternalAccessSet) map[string]proto.Message {
	out := map[string]proto.Message{}
	if accessSet == nil {
		return out
	}
	for _, rule := range accessSet.GetExternalRules() {
		if rule.GetExternalRuleId() != "" {
			out["external:"+rule.GetExternalRuleId()] = rule
		}
	}
	for _, rule := range accessSet.GetServiceRules() {
		if rule.GetServiceRuleId() != "" {
			out["service:"+rule.GetServiceRuleId()] = rule
		}
	}
	for _, endpoint := range accessSet.GetProxyEndpoints() {
		if endpoint.GetProxyEndpointId() != "" {
			out["proxy:"+endpoint.GetProxyEndpointId()] = endpoint
		}
	}
	for _, rule := range accessSet.GetHttpInspectionRules() {
		if rule.GetInspectionRuleId() != "" {
			out["http-inspection:"+rule.GetInspectionRuleId()] = rule
		}
	}
	return out
}
