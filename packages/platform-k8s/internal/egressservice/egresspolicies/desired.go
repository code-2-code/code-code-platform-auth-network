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
	destinations []*externalDestination
	httpRoutes   []*httpEgressRoute
}

type externalDestination struct {
	destinationID   string
	displayName     string
	host            string
	addressCidr     string
	port            int32
	protocol        egressv1.EgressProtocol
	resolution      egressv1.EgressResolution
	ownerServices   []string
	accessSetIDs    []string
	serviceAccounts []string
}

type httpEgressRoute struct {
	resourceID         string
	routeID            string
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
	httpRoutes := make([]*httpEgressRoute, 0)
	for _, accessSet := range policy.GetAccessSets() {
		for _, route := range accessSet.GetHttpRoutes() {
			httpRoute, err := httpRouteFromRule(accessSet, route, destinations)
			if err != nil {
				return desiredState{}, err
			}
			httpRoutes = append(httpRoutes, httpRoute)
		}
	}
	out := make([]*externalDestination, 0, len(destinations))
	for _, destination := range destinations {
		out = append(out, destination)
	}
	slices.SortFunc(out, func(a, b *externalDestination) int {
		return strings.Compare(a.destinationID, b.destinationID)
	})
	slices.SortFunc(httpRoutes, func(a, b *httpEgressRoute) int {
		return strings.Compare(a.resourceID, b.resourceID)
	})
	return desiredState{destinations: out, httpRoutes: httpRoutes}, nil
}

func destinationFromRule(accessSet *egressv1.ExternalAccessSet, rule *egressv1.ExternalRule) (*externalDestination, error) {
	host := rule.GetHostMatch().GetHostExact()
	if host == "" {
		host = rule.GetHostMatch().GetHostWildcard()
	}
	if host == "" {
		return nil, fmt.Errorf("external rule %q host is empty", rule.GetExternalRuleId())
	}
	return &externalDestination{
		destinationID: rule.GetDestinationId(),
		displayName:   displayNameOr(rule.GetDisplayName(), rule.GetDestinationId()),
		host:          host,
		addressCidr:   rule.GetAddressCidr(),
		port:          rule.GetPort(),
		protocol:      rule.GetProtocol(),
		resolution:    rule.GetResolution(),
		ownerServices: valueIfNotEmpty(accessSet.GetOwnerService()),
		accessSetIDs:  []string{accessSet.GetAccessSetId()},
	}, nil
}

func sameExternalDestination(a, b *externalDestination) bool {
	return a.host == b.host &&
		a.addressCidr == b.addressCidr &&
		a.port == b.port &&
		a.protocol == b.protocol &&
		a.resolution == b.resolution
}

func httpRouteFromRule(accessSet *egressv1.ExternalAccessSet, route *egressv1.HttpEgressRoute, destinations map[string]*externalDestination) (*httpEgressRoute, error) {
	destination, ok := destinations[route.GetDestinationId()]
	if !ok {
		return nil, fmt.Errorf("http route %q references unknown destination %q", route.GetRouteId(), route.GetDestinationId())
	}
	if strings.HasPrefix(destination.host, "*.") {
		return nil, fmt.Errorf("http route %q references wildcard destination %q; L7 header policy requires an exact host", route.GetRouteId(), destination.destinationID)
	}
	if destination.protocol != egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS {
		return nil, fmt.Errorf("http route %q references %s destination %q; L7 egress requires an HTTPS destination with TLS origination", route.GetRouteId(), protocolString(destination.protocol), destination.destinationID)
	}
	authPolicyID := strings.TrimSpace(route.GetAuthPolicyId())
	authProviderName, err := authProviderNameForRoute(authPolicyID, route.GetDynamicHeaderAuthz())
	if err != nil {
		return nil, fmt.Errorf("http route %q: %w", route.GetRouteId(), err)
	}
	return &httpEgressRoute{
		resourceID:         accessSet.GetAccessSetId() + "." + route.GetRouteId(),
		routeID:            route.GetRouteId(),
		displayName:        displayNameOr(route.GetDisplayName(), route.GetRouteId()),
		destination:        destination,
		matches:            httpRouteMatchesFromProto(route.GetMatches()),
		requestHeaders:     headerPolicyFromProto(route.GetRequestHeaders()),
		responseHeaders:    headerPolicyFromProto(route.GetResponseHeaders()),
		authPolicyID:       authPolicyID,
		authProviderName:   authProviderName,
		dynamicHeaderAuthz: route.GetDynamicHeaderAuthz(),
		ownerServices:      valueIfNotEmpty(accessSet.GetOwnerService()),
		accessSetIDs:       []string{accessSet.GetAccessSetId()},
	}, nil
}

func authProviderNameForRoute(authPolicyID string, dynamicHeaderAuthz bool) (string, error) {
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
	added     int32
	updated   int32
	removed   int32
	unchanged int32
}

func diffAccessSet(before, after *egressv1.ExternalAccessSet) accessSetDiff {
	beforeRules := accessSetItemMap(before)
	afterRules := accessSetItemMap(after)
	var diff accessSetDiff
	for id, next := range afterRules {
		prev, ok := beforeRules[id]
		if !ok {
			diff.added++
			continue
		}
		if proto.Equal(prev, next) {
			diff.unchanged++
		} else {
			diff.updated++
		}
	}
	for id := range beforeRules {
		if _, ok := afterRules[id]; !ok {
			diff.removed++
		}
	}
	return diff
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
	for _, route := range accessSet.GetHttpRoutes() {
		if route.GetRouteId() != "" {
			out["http:"+route.GetRouteId()] = route
		}
	}
	return out
}
