package egresspolicies

import (
	"fmt"
	"slices"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type authorizationGroup struct {
	groupID         string
	serviceAccounts []string
	destinations    []*externalDestination
}

func groupedAuthorizations(destinations []*externalDestination) []*authorizationGroup {
	groupsByKey := map[string]*authorizationGroup{}
	for _, destination := range destinations {
		serviceAccounts := mergeValues(nil, destination.serviceAccounts)
		key := authorizationGroupKey(serviceAccounts)
		group, ok := groupsByKey[key]
		if !ok {
			group = &authorizationGroup{
				groupID:         key,
				serviceAccounts: serviceAccounts,
			}
			groupsByKey[key] = group
		}
		group.destinations = append(group.destinations, destination)
	}
	groups := make([]*authorizationGroup, 0, len(groupsByKey))
	for _, group := range groupsByKey {
		slices.SortFunc(group.destinations, func(a, b *externalDestination) int {
			return strings.Compare(a.destinationID, b.destinationID)
		})
		groups = append(groups, group)
	}
	slices.SortFunc(groups, func(a, b *authorizationGroup) int {
		return strings.Compare(a.groupID, b.groupID)
	})
	return groups
}

func authorizationGroupKey(serviceAccounts []string) string {
	if len(serviceAccounts) == 0 {
		return "deny-all"
	}
	return "sources-" + strings.Join(serviceAccounts, "-")
}

func authorizationPolicyObject(runtime egressRuntime, group *authorizationGroup) ctrlclient.Object {
	spec := map[string]any{
		"targetRefs": authorizationTargetRefs(group.destinations),
		"action":     "ALLOW",
		"rules":      []any{},
	}
	if len(group.serviceAccounts) > 0 {
		spec["rules"] = []any{map[string]any{
			"from": []any{map[string]any{
				"source": map[string]any{
					"serviceAccounts": stringSliceAny(group.serviceAccounts),
				},
			}},
		}}
	}
	return newObject(
		authorizationPolicyGVK,
		runtime.namespace,
		authorizationPolicyName(group.groupID),
		authorizationLabels(),
		authorizationAnnotations(group),
		spec,
	)
}

func authorizationTargetRefs(destinations []*externalDestination) []any {
	refs := make([]any, 0, len(destinations))
	seen := map[string]struct{}{}
	for _, destination := range destinations {
		name := serviceEntryNameForDestination(destination)
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		refs = append(refs, map[string]any{
			"group": "networking.istio.io",
			"kind":  "ServiceEntry",
			"name":  name,
		})
	}
	return refs
}

func proxyEndpointAuthorizationPolicyObject(runtime egressRuntime, endpoints []*proxyEndpoint) ctrlclient.Object {
	spec := map[string]any{
		"targetRefs": proxyEndpointAuthorizationTargetRefs(endpoints),
		"action":     "ALLOW",
		"rules": []any{map[string]any{
			"from": []any{map[string]any{
				"source": map[string]any{
					"serviceAccounts": []any{runtime.namespace + "/" + egressForwarderSAName},
				},
			}},
		}},
	}
	return newObject(
		authorizationPolicyGVK,
		runtime.namespace,
		resourceNameProxyAuthz,
		mergeStringMaps(gatewayLabels(), map[string]string{labelEgressRole: egressRoleProxyAuthz}),
		map[string]string{annotationDisplayName: "Authorization for egress forwarders to proxy endpoints"},
		spec,
	)
}

func proxyEndpointAuthorizationTargetRefs(endpoints []*proxyEndpoint) []any {
	refs := make([]any, 0, len(endpoints))
	for _, endpoint := range endpoints {
		refs = append(refs, map[string]any{
			"group": "networking.istio.io",
			"kind":  "ServiceEntry",
			"name":  proxyEndpointServiceEntryName(endpoint.proxyEndpointID),
		})
	}
	return refs
}

type dynamicHeaderAuthzRouteGroup struct {
	providerName string
	routes       []*httpInspectionRule
}

func dynamicHeaderAuthzRoutes(routes []*httpInspectionRule) []*httpInspectionRule {
	out := make([]*httpInspectionRule, 0, len(routes))
	for _, route := range routes {
		if route.dynamicHeaderAuthz {
			out = append(out, route)
		}
	}
	slices.SortFunc(out, func(a, b *httpInspectionRule) int {
		return strings.Compare(a.resourceID, b.resourceID)
	})
	return out
}

func dynamicHeaderAuthzRouteGroups(runtime egressRuntime, routes []*httpInspectionRule) []*dynamicHeaderAuthzRouteGroup {
	groupsByProvider := map[string]*dynamicHeaderAuthzRouteGroup{}
	for _, route := range routes {
		providerName := dynamicHeaderAuthzProviderNameForRoute(runtime, route)
		group, ok := groupsByProvider[providerName]
		if !ok {
			group = &dynamicHeaderAuthzRouteGroup{providerName: providerName}
			groupsByProvider[providerName] = group
		}
		group.routes = append(group.routes, route)
	}
	groups := make([]*dynamicHeaderAuthzRouteGroup, 0, len(groupsByProvider))
	for _, group := range groupsByProvider {
		slices.SortFunc(group.routes, func(a, b *httpInspectionRule) int {
			return strings.Compare(a.resourceID, b.resourceID)
		})
		groups = append(groups, group)
	}
	slices.SortFunc(groups, func(a, b *dynamicHeaderAuthzRouteGroup) int {
		return strings.Compare(a.providerName, b.providerName)
	})
	return groups
}

func dynamicHeaderAuthzProviderNameForRoute(runtime egressRuntime, route *httpInspectionRule) string {
	if route != nil {
		if providerName := strings.TrimSpace(route.authProviderName); providerName != "" {
			return providerName
		}
	}
	return runtime.dynamicHeaderAuthzProviderName
}

func dynamicHeaderAuthzPolicyObject(runtime egressRuntime, group *dynamicHeaderAuthzRouteGroup) ctrlclient.Object {
	spec := map[string]any{
		"targetRefs": dynamicHeaderAuthzTargetRefs(group.routes),
		"action":     "CUSTOM",
		"provider": map[string]any{
			"name": group.providerName,
		},
		"rules": dynamicHeaderAuthzRules(group.routes),
	}
	return newObject(
		authorizationPolicyGVK,
		runtime.namespace,
		dynamicHeaderAuthzPolicyName(group.providerName),
		dynamicHeaderAuthzLabels(),
		dynamicHeaderAuthzAnnotations(group.providerName, group.routes),
		spec,
	)
}

func dynamicHeaderAuthzTargetRefs(routes []*httpInspectionRule) []any {
	destinations := l7EgressDestinations(routes)
	refs := make([]any, 0, len(destinations))
	for _, destination := range destinations {
		refs = append(refs, map[string]any{
			"group": "networking.istio.io",
			"kind":  "ServiceEntry",
			"name":  serviceEntryNameForDestination(destination),
		})
	}
	return refs
}

func dynamicHeaderAuthzRules(routes []*httpInspectionRule) []any {
	rules := make([]any, 0, len(routes))
	for _, route := range routes {
		operations := dynamicHeaderAuthzOperations(route)
		if len(operations) == 0 {
			continue
		}
		rules = append(rules, map[string]any{
			"to": operations,
		})
	}
	return rules
}

func dynamicHeaderAuthzOperations(route *httpInspectionRule) []any {
	if len(route.matches) == 0 {
		return []any{map[string]any{"operation": map[string]any{
			"hosts": []any{route.destination.host},
		}}}
	}
	operations := make([]any, 0, len(route.matches))
	for _, match := range route.matches {
		operation := map[string]any{
			"hosts": []any{route.destination.host},
		}
		if len(match.methods) > 0 {
			operation["methods"] = stringSliceAny(match.methods)
		}
		if paths := authzPaths(match.pathPrefixes); len(paths) > 0 {
			operation["paths"] = paths
		}
		operations = append(operations, map[string]any{"operation": operation})
	}
	return operations
}

func authzPaths(pathPrefixes []string) []any {
	out := make([]any, 0, len(pathPrefixes))
	for _, prefix := range pathPrefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" || prefix == "/" {
			continue
		}
		out = append(out, strings.TrimRight(prefix, "/")+"*")
	}
	return out
}

func l7EgressDestinations(routes []*httpInspectionRule) []*externalDestination {
	seen := map[string]*externalDestination{}
	for _, route := range routes {
		if route.destination.protocol != egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS {
			continue
		}
		seen[route.destination.destinationID] = route.destination
	}
	out := make([]*externalDestination, 0, len(seen))
	for _, destination := range seen {
		out = append(out, destination)
	}
	slices.SortFunc(out, func(a, b *externalDestination) int {
		return strings.Compare(a.destinationID, b.destinationID)
	})
	return out
}

func directL7EgressDestinations(routes []*httpInspectionRule) []*externalDestination {
	seen := map[string]*externalDestination{}
	for _, route := range routes {
		if route.destination.protocol != egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS {
			continue
		}
		seen[route.destination.destinationID] = route.destination
	}
	out := make([]*externalDestination, 0, len(seen))
	for _, destination := range seen {
		out = append(out, destination)
	}
	slices.SortFunc(out, func(a, b *externalDestination) int {
		return strings.Compare(a.destinationID, b.destinationID)
	})
	return out
}

func proxyEgressDestinations(destinations []*externalDestination) []*externalDestination {
	out := make([]*externalDestination, 0)
	for _, destination := range destinations {
		if destination.proxyEndpoint != nil {
			out = append(out, destination)
		}
	}
	slices.SortFunc(out, func(a, b *externalDestination) int {
		return strings.Compare(a.destinationID, b.destinationID)
	})
	return out
}

type proxyEndpointDestinationGroup struct {
	routeID       string
	proxyEndpoint *proxyEndpoint
	destinations  []*externalDestination
	ownerServices []string
	accessSetIDs  []string
}

func proxyEndpointDestinationGroups(destinations []*externalDestination) []*proxyEndpointDestinationGroup {
	groupsByProxy := map[string]*proxyEndpointDestinationGroup{}
	for _, destination := range destinations {
		if destination.proxyEndpoint == nil {
			continue
		}
		group, ok := groupsByProxy[destination.proxyEndpoint.proxyEndpointID]
		if !ok {
			group = &proxyEndpointDestinationGroup{
				routeID:       destination.proxyEndpoint.proxyEndpointID,
				proxyEndpoint: destination.proxyEndpoint,
			}
			groupsByProxy[destination.proxyEndpoint.proxyEndpointID] = group
		}
		group.destinations = append(group.destinations, destination)
		group.ownerServices = mergeValues(group.ownerServices, destination.ownerServices)
		group.accessSetIDs = mergeValues(group.accessSetIDs, destination.accessSetIDs)
	}
	out := make([]*proxyEndpointDestinationGroup, 0, len(groupsByProxy))
	for _, group := range groupsByProxy {
		slices.SortFunc(group.destinations, func(a, b *externalDestination) int {
			return strings.Compare(a.destinationID, b.destinationID)
		})
		out = append(out, group)
	}
	slices.SortFunc(out, func(a, b *proxyEndpointDestinationGroup) int {
		return strings.Compare(a.proxyEndpoint.proxyEndpointID, b.proxyEndpoint.proxyEndpointID)
	})
	return out
}

func proxyEndpointTLSRouteGroups(group *proxyEndpointDestinationGroup) []*proxyEndpointDestinationGroup {
	if len(group.destinations) <= gatewayAPIMaxHostnames {
		return []*proxyEndpointDestinationGroup{group}
	}
	out := make([]*proxyEndpointDestinationGroup, 0, (len(group.destinations)+gatewayAPIMaxHostnames-1)/gatewayAPIMaxHostnames)
	for start := 0; start < len(group.destinations); start += gatewayAPIMaxHostnames {
		end := min(start+gatewayAPIMaxHostnames, len(group.destinations))
		out = append(out, &proxyEndpointDestinationGroup{
			routeID:       fmt.Sprintf("%s-%02d", group.proxyEndpoint.proxyEndpointID, len(out)+1),
			proxyEndpoint: group.proxyEndpoint,
			destinations:  append([]*externalDestination(nil), group.destinations[start:end]...),
			ownerServices: append([]string(nil), group.ownerServices...),
			accessSetIDs:  append([]string(nil), group.accessSetIDs...),
		})
	}
	return out
}
