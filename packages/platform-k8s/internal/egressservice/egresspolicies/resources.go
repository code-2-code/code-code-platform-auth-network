package egresspolicies

import (
	"context"
	"fmt"
	"slices"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	configMapGVK     = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"}
	configMapListGVK = schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "ConfigMapList",
	}
	gatewayGVK     = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "Gateway"}
	gatewayListGVK = schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1",
		Kind:    "GatewayList",
	}
	httpRouteGVK     = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
	httpRouteListGVK = schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1",
		Kind:    "HTTPRouteList",
	}
	serviceEntryGVK     = schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1", Kind: "ServiceEntry"}
	serviceEntryListGVK = schema.GroupVersionKind{
		Group:   "networking.istio.io",
		Version: "v1",
		Kind:    "ServiceEntryList",
	}
	destinationRuleGVK     = schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1", Kind: "DestinationRule"}
	destinationRuleListGVK = schema.GroupVersionKind{
		Group:   "networking.istio.io",
		Version: "v1",
		Kind:    "DestinationRuleList",
	}
	authorizationPolicyGVK     = schema.GroupVersionKind{Group: "security.istio.io", Version: "v1", Kind: "AuthorizationPolicy"}
	authorizationPolicyListGVK = schema.GroupVersionKind{
		Group:   "security.istio.io",
		Version: "v1",
		Kind:    "AuthorizationPolicyList",
	}
)

func desiredObjects(runtime egressRuntime, desired desiredState) []ctrlclient.Object {
	authorizationGroups := groupedAuthorizations(desired.destinations)
	dynamicAuthzRoutes := dynamicHeaderAuthzRoutes(desired.httpRoutes)
	dynamicAuthzGroups := dynamicHeaderAuthzRouteGroups(runtime, dynamicAuthzRoutes)
	l7Destinations := l7EgressDestinations(desired.httpRoutes)
	capacity := len(desired.destinations) + len(authorizationGroups) + len(desired.httpRoutes)*2 + len(l7Destinations)*4
	capacity += len(dynamicAuthzGroups)
	objects := make([]ctrlclient.Object, 0, capacity)
	for _, destination := range desired.destinations {
		objects = append(objects, serviceEntryObject(runtime, destination))
	}
	for _, group := range authorizationGroups {
		objects = append(objects, authorizationPolicyObject(runtime, group))
	}
	for _, group := range dynamicAuthzGroups {
		objects = append(objects, dynamicHeaderAuthzPolicyObject(runtime, group))
	}
	for _, destination := range l7Destinations {
		objects = append(objects, l7EgressGatewayOptionsObject(runtime, destination))
		objects = append(objects, l7EgressGatewayObject(runtime, destination))
		objects = append(objects, egressGatewayDestinationRuleObject(runtime, destination))
	}
	for _, route := range desired.httpRoutes {
		objects = append(objects, directHTTPRouteObject(runtime, route))
		objects = append(objects, forwardHTTPRouteObject(runtime, route))
	}
	for _, destination := range l7Destinations {
		objects = append(objects, tlsOriginationDestinationRuleObject(runtime, destination))
	}
	return objects
}

func serviceEntryObject(runtime egressRuntime, destination *externalDestination) ctrlclient.Object {
	spec := map[string]any{
		"hosts":      []any{destination.host},
		"location":   "MESH_EXTERNAL",
		"ports":      serviceEntryPorts(destination),
		"resolution": resolutionString(destination.resolution),
	}
	if destination.addressCidr != "" {
		spec["addresses"] = []any{destination.addressCidr}
	}
	labels := resourceLabels(egressRoleDestination, destination)
	labels["istio.io/use-waypoint"] = egressWaypointName
	labels["istio.io/use-waypoint-namespace"] = runtime.namespace
	return newObject(
		serviceEntryGVK,
		runtime.namespace,
		serviceEntryName(destination.destinationID),
		labels,
		resourceAnnotations(destination),
		spec,
	)
}

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

func l7EgressGatewayObject(runtime egressRuntime, destination *externalDestination) ctrlclient.Object {
	spec := map[string]any{
		"infrastructure": map[string]any{
			"parametersRef": map[string]any{
				"group": "",
				"kind":  "ConfigMap",
				"name":  l7EgressGatewayOptionsName(destination.destinationID),
			},
		},
		"gatewayClassName": "istio",
		"listeners": []any{map[string]any{
			"name":     "https-tls-origination",
			"hostname": destination.host,
			"port":     int64(l7EgressClientHTTPPort),
			"protocol": "HTTPS",
			"tls": map[string]any{
				"mode": "Terminate",
				"options": map[string]any{
					"gateway.istio.io/tls-terminate-mode": "ISTIO_MUTUAL",
				},
			},
			"allowedRoutes": map[string]any{
				"namespaces": map[string]any{
					"from": "Same",
				},
			},
		}},
	}
	return newObject(
		gatewayGVK,
		runtime.namespace,
		l7EgressGatewayName(destination.destinationID),
		resourceLabels(egressRoleL7Gateway, destination),
		resourceAnnotations(destination),
		spec,
	)
}

func l7EgressGatewayOptionsObject(runtime egressRuntime, destination *externalDestination) ctrlclient.Object {
	return newConfigMapObject(
		runtime.namespace,
		l7EgressGatewayOptionsName(destination.destinationID),
		resourceLabels(egressRoleL7GatewayOptions, destination),
		resourceAnnotations(destination),
		map[string]string{
			"service": "spec:\n  type: ClusterIP",
		},
	)
}

func egressGatewayDestinationRuleObject(runtime egressRuntime, destination *externalDestination) ctrlclient.Object {
	spec := map[string]any{
		"host": l7EgressGatewayServiceHost(runtime, destination),
		"trafficPolicy": map[string]any{
			"loadBalancer": map[string]any{"simple": "ROUND_ROBIN"},
			"portLevelSettings": []any{map[string]any{
				"port": map[string]any{
					"number": int64(l7EgressClientHTTPPort),
				},
				"tls": map[string]any{
					"mode": "ISTIO_MUTUAL",
					"sni":  destination.host,
				},
			}},
		},
	}
	return newObject(
		destinationRuleGVK,
		runtime.namespace,
		gatewayDestinationRuleName(destination.destinationID),
		resourceLabels(egressRoleGatewayMTLS, destination),
		resourceAnnotations(destination),
		spec,
	)
}

func l7EgressGatewayServiceHost(runtime egressRuntime, destination *externalDestination) string {
	return l7EgressGatewayServiceName(destination.destinationID) + "." + runtime.namespace + ".svc.cluster.local"
}

type dynamicHeaderAuthzRouteGroup struct {
	providerName string
	routes       []*httpEgressRoute
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

func directHTTPRouteObject(runtime egressRuntime, route *httpEgressRoute) ctrlclient.Object {
	spec := map[string]any{
		"parentRefs": []any{map[string]any{
			"group": "networking.istio.io",
			"kind":  "ServiceEntry",
			"name":  serviceEntryName(route.destination.destinationID),
		}},
		"rules": []any{map[string]any{
			"backendRefs": []any{map[string]any{
				"name": l7EgressGatewayServiceName(route.destination.destinationID),
				"port": int64(l7EgressClientHTTPPort),
			}},
		}},
	}
	return newObject(
		httpRouteGVK,
		runtime.namespace,
		directHTTPRouteName(route.resourceID),
		httpRouteLabels(egressRoleDirectHTTPRoute, route),
		httpRouteAnnotations(route),
		spec,
	)
}

func forwardHTTPRouteObject(runtime egressRuntime, route *httpEgressRoute) ctrlclient.Object {
	rule := map[string]any{
		"backendRefs": []any{map[string]any{
			"group": "networking.istio.io",
			"kind":  "Hostname",
			"name":  route.destination.host,
			"port":  int64(route.destination.port),
		}},
	}
	if matches := httpRouteMatches(route.matches); len(matches) > 0 {
		rule["matches"] = matches
	}
	if filters := headerModifierFilters(route); len(filters) > 0 {
		rule["filters"] = filters
	}
	spec := map[string]any{
		"parentRefs": []any{map[string]any{
			"name": l7EgressGatewayName(route.destination.destinationID),
		}},
		"hostnames": []any{route.destination.host},
		"rules":     []any{rule},
	}
	return newObject(
		httpRouteGVK,
		runtime.namespace,
		forwardHTTPRouteName(route.resourceID),
		httpRouteLabels(egressRoleForwardHTTPRoute, route),
		httpRouteAnnotations(route),
		spec,
	)
}

func tlsOriginationDestinationRuleObject(runtime egressRuntime, destination *externalDestination) ctrlclient.Object {
	spec := map[string]any{
		"host": destination.host,
		"trafficPolicy": map[string]any{
			"loadBalancer": map[string]any{"simple": "ROUND_ROBIN"},
			"portLevelSettings": []any{map[string]any{
				"port": map[string]any{
					"number": int64(destination.port),
				},
				"tls": map[string]any{
					"mode":           "SIMPLE",
					"sni":            destination.host,
					"caCertificates": "system",
				},
			}},
		},
	}
	return newObject(
		destinationRuleGVK,
		runtime.namespace,
		destinationRuleName(destination.destinationID),
		resourceLabels(egressRoleTLSOrigination, destination),
		resourceAnnotations(destination),
		spec,
	)
}

func dynamicHeaderAuthzRoutes(routes []*httpEgressRoute) []*httpEgressRoute {
	out := make([]*httpEgressRoute, 0, len(routes))
	for _, route := range routes {
		if route.dynamicHeaderAuthz {
			out = append(out, route)
		}
	}
	slices.SortFunc(out, func(a, b *httpEgressRoute) int {
		return strings.Compare(a.resourceID, b.resourceID)
	})
	return out
}

func dynamicHeaderAuthzRouteGroups(runtime egressRuntime, routes []*httpEgressRoute) []*dynamicHeaderAuthzRouteGroup {
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
		slices.SortFunc(group.routes, func(a, b *httpEgressRoute) int {
			return strings.Compare(a.resourceID, b.resourceID)
		})
		groups = append(groups, group)
	}
	slices.SortFunc(groups, func(a, b *dynamicHeaderAuthzRouteGroup) int {
		return strings.Compare(a.providerName, b.providerName)
	})
	return groups
}

func dynamicHeaderAuthzProviderNameForRoute(runtime egressRuntime, route *httpEgressRoute) string {
	if route != nil {
		if providerName := strings.TrimSpace(route.authProviderName); providerName != "" {
			return providerName
		}
	}
	return runtime.dynamicHeaderAuthzProviderName
}

func dynamicHeaderAuthzTargetRefs(routes []*httpEgressRoute) []any {
	destinations := l7EgressDestinations(routes)
	refs := make([]any, 0, len(destinations))
	for _, destination := range destinations {
		refs = append(refs, map[string]any{
			"group": "networking.istio.io",
			"kind":  "ServiceEntry",
			"name":  serviceEntryName(destination.destinationID),
		})
	}
	return refs
}

func dynamicHeaderAuthzRules(routes []*httpEgressRoute) []any {
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

func dynamicHeaderAuthzOperations(route *httpEgressRoute) []any {
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

func l7EgressDestinations(routes []*httpEgressRoute) []*externalDestination {
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

func httpRouteMatches(matches []*httpRouteMatch) []any {
	var out []any
	for _, match := range matches {
		switch {
		case len(match.pathPrefixes) > 0 && len(match.methods) > 0:
			for _, pathPrefix := range match.pathPrefixes {
				for _, method := range match.methods {
					out = append(out, httpRouteMatchSpec(pathPrefix, method))
				}
			}
		case len(match.pathPrefixes) > 0:
			for _, pathPrefix := range match.pathPrefixes {
				out = append(out, httpRouteMatchSpec(pathPrefix, ""))
			}
		case len(match.methods) > 0:
			for _, method := range match.methods {
				out = append(out, httpRouteMatchSpec("", method))
			}
		}
	}
	return out
}

func httpRouteMatchSpec(pathPrefix string, method string) map[string]any {
	out := map[string]any{}
	if pathPrefix != "" {
		out["path"] = map[string]any{
			"type":  "PathPrefix",
			"value": pathPrefix,
		}
	}
	if method != "" {
		out["method"] = method
	}
	return out
}

func headerModifierFilters(route *httpEgressRoute) []any {
	var filters []any
	if modifier := headerModifier(route.requestHeaders); len(modifier) > 0 {
		filters = append(filters, map[string]any{
			"type":                  "RequestHeaderModifier",
			"requestHeaderModifier": modifier,
		})
	}
	if modifier := headerModifier(route.responseHeaders); len(modifier) > 0 {
		filters = append(filters, map[string]any{
			"type":                   "ResponseHeaderModifier",
			"responseHeaderModifier": modifier,
		})
	}
	return filters
}

func headerModifier(policy headerPolicy) map[string]any {
	out := map[string]any{}
	if len(policy.add) > 0 {
		out["add"] = headerValues(policy.add)
	}
	if len(policy.set) > 0 {
		out["set"] = headerValues(policy.set)
	}
	if len(policy.remove) > 0 {
		out["remove"] = stringSliceAny(policy.remove)
	}
	return out
}

func headerValues(values []headerValue) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, map[string]any{
			"name":  value.name,
			"value": value.value,
		})
	}
	return out
}

func authorizationTargetRefs(destinations []*externalDestination) []any {
	refs := make([]any, 0, len(destinations))
	for _, destination := range destinations {
		refs = append(refs, map[string]any{
			"group": "networking.istio.io",
			"kind":  "ServiceEntry",
			"name":  serviceEntryName(destination.destinationID),
		})
	}
	return refs
}

func httpRouteLabels(role string, route *httpEgressRoute) map[string]string {
	return mergeStringMaps(resourceLabels(role, route.destination), map[string]string{
		labelEgressRoute: destinationLabelValue(route.resourceID),
	})
}

func newObject(gvk schema.GroupVersionKind, namespace string, name string, labels map[string]string, annotations map[string]string, spec map[string]any) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	obj.SetGroupVersionKind(gvk)
	obj.SetNamespace(namespace)
	obj.SetName(name)
	obj.SetLabels(labels)
	obj.SetAnnotations(annotations)
	return obj
}

func newConfigMapObject(namespace string, name string, labels map[string]string, annotations map[string]string, data map[string]string) *unstructured.Unstructured {
	dataObject := make(map[string]any, len(data))
	for key, value := range data {
		dataObject[key] = value
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"data": dataObject,
	}}
	obj.SetGroupVersionKind(configMapGVK)
	obj.SetNamespace(namespace)
	obj.SetName(name)
	obj.SetLabels(labels)
	obj.SetAnnotations(annotations)
	return obj
}

func resourceLabels(role string, destination *externalDestination) map[string]string {
	return mergeStringMaps(gatewayLabels(), map[string]string{
		labelEgressRole:        role,
		labelEgressDestination: destinationLabelValue(destination.destinationID),
	})
}

func authorizationLabels() map[string]string {
	return mergeStringMaps(gatewayLabels(), map[string]string{
		labelEgressRole: egressRoleAuthorization,
	})
}

func dynamicHeaderAuthzLabels() map[string]string {
	return mergeStringMaps(gatewayLabels(), map[string]string{
		labelEgressRole: egressRoleDynamicAuthz,
	})
}

func resourceAnnotations(destination *externalDestination) map[string]string {
	return map[string]string{
		annotationDisplayName:   destination.displayName,
		annotationDestinationID: destination.destinationID,
		annotationOwnerService:  strings.Join(destination.ownerServices, ","),
		labelEgressAccessSetID:  strings.Join(destination.accessSetIDs, ","),
	}
}

func authorizationAnnotations(group *authorizationGroup) map[string]string {
	return map[string]string{
		annotationDisplayName:   "Authorization for " + authorizationDisplayName(group.serviceAccounts),
		annotationDestinationID: strings.Join(authorizationDestinationIDs(group.destinations), ","),
		annotationOwnerService:  strings.Join(authorizationOwnerServices(group.destinations), ","),
		labelEgressAccessSetID:  strings.Join(authorizationAccessSetIDs(group.destinations), ","),
	}
}

func dynamicHeaderAuthzAnnotations(providerName string, routes []*httpEgressRoute) map[string]string {
	return map[string]string{
		annotationDisplayName:   "Dynamic header authorization for " + providerName,
		annotationDestinationID: strings.Join(dynamicHeaderAuthzDestinationIDs(routes), ","),
		annotationOwnerService:  strings.Join(dynamicHeaderAuthzOwnerServices(routes), ","),
		labelEgressAccessSetID:  strings.Join(dynamicHeaderAuthzAccessSetIDs(routes), ","),
	}
}

func httpRouteAnnotations(route *httpEgressRoute) map[string]string {
	return map[string]string{
		annotationDisplayName:                 route.displayName,
		annotationDestinationID:               route.destination.destinationID,
		annotationOwnerService:                strings.Join(route.ownerServices, ","),
		labelEgressAccessSetID:                strings.Join(route.accessSetIDs, ","),
		labelEgressRoute:                      route.routeID,
		egressLabelPrefix + "/auth-policy-id": strings.TrimSpace(route.authPolicyID),
	}
}

func authorizationDisplayName(serviceAccounts []string) string {
	if len(serviceAccounts) == 0 {
		return "no source service accounts"
	}
	return strings.Join(serviceAccounts, ", ")
}

func authorizationDestinationIDs(destinations []*externalDestination) []string {
	out := make([]string, 0, len(destinations))
	for _, destination := range destinations {
		out = append(out, destination.destinationID)
	}
	return mergeValues(nil, out)
}

func authorizationOwnerServices(destinations []*externalDestination) []string {
	var out []string
	for _, destination := range destinations {
		out = mergeValues(out, destination.ownerServices)
	}
	return out
}

func authorizationAccessSetIDs(destinations []*externalDestination) []string {
	var out []string
	for _, destination := range destinations {
		out = mergeValues(out, destination.accessSetIDs)
	}
	return out
}

func dynamicHeaderAuthzDestinationIDs(routes []*httpEgressRoute) []string {
	out := make([]string, 0, len(routes))
	for _, route := range routes {
		out = append(out, route.destination.destinationID)
	}
	return mergeValues(nil, out)
}

func dynamicHeaderAuthzOwnerServices(routes []*httpEgressRoute) []string {
	var out []string
	for _, route := range routes {
		out = mergeValues(out, route.ownerServices)
	}
	return out
}

func dynamicHeaderAuthzAccessSetIDs(routes []*httpEgressRoute) []string {
	var out []string
	for _, route := range routes {
		out = mergeValues(out, route.accessSetIDs)
	}
	return out
}

func serviceEntryPort(protocolValue egressv1.EgressProtocol, port int32) map[string]any {
	protocol := protocolString(protocolValue)
	return map[string]any{
		"number":   int64(port),
		"name":     strings.ToLower(protocol) + "-" + fmt.Sprint(port),
		"protocol": protocol,
	}
}

func serviceEntryPorts(destination *externalDestination) []any {
	if destination.protocol == egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS {
		ports := []any{serviceEntryPort(egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTP, l7EgressClientHTTPPort)}
		if destination.port != l7EgressClientHTTPPort {
			ports = append(ports, serviceEntryPort(egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS, destination.port))
		}
		return ports
	}
	return []any{serviceEntryPort(destination.protocol, destination.port)}
}

func protocolString(protocol egressv1.EgressProtocol) string {
	switch protocol {
	case egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTP:
		return "HTTP"
	case egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS:
		return "TLS"
	case egressv1.EgressProtocol_EGRESS_PROTOCOL_TCP:
		return "TCP"
	case egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS:
		return "HTTPS"
	default:
		return "TLS"
	}
}

func resolutionString(resolution egressv1.EgressResolution) string {
	switch resolution {
	case egressv1.EgressResolution_EGRESS_RESOLUTION_DNS:
		return "DNS"
	case egressv1.EgressResolution_EGRESS_RESOLUTION_DYNAMIC_DNS:
		return "DYNAMIC_DNS"
	case egressv1.EgressResolution_EGRESS_RESOLUTION_NONE:
		return "NONE"
	default:
		return "DNS"
	}
}

func stringSliceAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func (s *Service) applyGeneratedObjects(ctx context.Context, objects []ctrlclient.Object) error {
	for _, obj := range objects {
		if err := s.client.Patch(ctx, obj, ctrlclient.Apply, ctrlclient.FieldOwner(fieldOwner), ctrlclient.ForceOwnership); err != nil {
			return fmt.Errorf("apply %s %s/%s: %w", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetNamespace(), obj.GetName(), err)
		}
	}
	if err := s.deleteStaleManagedObjects(ctx, objects); err != nil {
		return err
	}
	return nil
}

func (s *Service) deleteStaleManagedObjects(ctx context.Context, objects []ctrlclient.Object) error {
	desired := map[string]map[string]struct{}{}
	for _, obj := range objects {
		key := obj.GetObjectKind().GroupVersionKind().String() + "|" + obj.GetNamespace()
		if desired[key] == nil {
			desired[key] = map[string]struct{}{}
		}
		desired[key][obj.GetName()] = struct{}{}
	}
	targets := []managedResourceType{
		{gvk: serviceEntryGVK, listGVK: serviceEntryListGVK, role: egressRoleDestination},
		{gvk: authorizationPolicyGVK, listGVK: authorizationPolicyListGVK, role: egressRoleAuthorization},
		{gvk: authorizationPolicyGVK, listGVK: authorizationPolicyListGVK, role: egressRoleDynamicAuthz},
		{gvk: configMapGVK, listGVK: configMapListGVK, role: egressRoleL7GatewayOptions},
		{gvk: gatewayGVK, listGVK: gatewayListGVK, role: egressRoleL7Gateway},
		{gvk: destinationRuleGVK, listGVK: destinationRuleListGVK, role: egressRoleGatewayMTLS},
		{gvk: httpRouteGVK, listGVK: httpRouteListGVK, role: egressRoleDirectHTTPRoute},
		{gvk: httpRouteGVK, listGVK: httpRouteListGVK, role: egressRoleForwardHTTPRoute},
		{gvk: destinationRuleGVK, listGVK: destinationRuleListGVK, role: egressRoleTLSOrigination},
	}
	for _, target := range targets {
		key := target.gvk.String() + "|" + s.egressRuntime.namespace
		if err := s.deleteStaleForType(ctx, target, s.egressRuntime.namespace, desired[key]); err != nil {
			return err
		}
	}
	return nil
}

type managedResourceType struct {
	gvk     schema.GroupVersionKind
	listGVK schema.GroupVersionKind
	role    string
}

func (s *Service) deleteStaleForType(ctx context.Context, target managedResourceType, namespace string, desiredNames map[string]struct{}) error {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(target.listGVK)
	selector := mergeStringMaps(gatewayLabels(), map[string]string{labelEgressRole: target.role})
	if err := s.client.List(ctx, list, ctrlclient.InNamespace(namespace), ctrlclient.MatchingLabels(selector)); err != nil {
		return fmt.Errorf("list stale %s in %s: %w", target.gvk.Kind, namespace, err)
	}
	for _, item := range list.Items {
		if _, ok := desiredNames[item.GetName()]; ok {
			continue
		}
		obj := item.DeepCopy()
		obj.SetGroupVersionKind(target.gvk)
		if err := s.client.Delete(ctx, obj); err != nil {
			return fmt.Errorf("delete stale %s %s/%s: %w", target.gvk.Kind, namespace, obj.GetName(), err)
		}
	}
	return nil
}

func resourceRefsFromObjects(objects []ctrlclient.Object) []*egressv1.EgressResourceRef {
	refs := make([]*egressv1.EgressResourceRef, 0, len(objects))
	for _, obj := range objects {
		refs = append(refs, &egressv1.EgressResourceRef{
			Kind:      obj.GetObjectKind().GroupVersionKind().Kind,
			Namespace: obj.GetNamespace(),
			Name:      obj.GetName(),
		})
	}
	sortResourceRefs(refs)
	return refs
}

func (s *Service) currentResourceRefs(ctx context.Context) ([]*egressv1.EgressResourceRef, error) {
	targets := []managedResourceType{
		{gvk: serviceEntryGVK, listGVK: serviceEntryListGVK, role: egressRoleDestination},
		{gvk: authorizationPolicyGVK, listGVK: authorizationPolicyListGVK, role: egressRoleAuthorization},
		{gvk: authorizationPolicyGVK, listGVK: authorizationPolicyListGVK, role: egressRoleDynamicAuthz},
		{gvk: configMapGVK, listGVK: configMapListGVK, role: egressRoleL7GatewayOptions},
		{gvk: gatewayGVK, listGVK: gatewayListGVK, role: egressRoleL7Gateway},
		{gvk: destinationRuleGVK, listGVK: destinationRuleListGVK, role: egressRoleGatewayMTLS},
		{gvk: httpRouteGVK, listGVK: httpRouteListGVK, role: egressRoleDirectHTTPRoute},
		{gvk: httpRouteGVK, listGVK: httpRouteListGVK, role: egressRoleForwardHTTPRoute},
		{gvk: destinationRuleGVK, listGVK: destinationRuleListGVK, role: egressRoleTLSOrigination},
	}
	var refs []*egressv1.EgressResourceRef
	for _, target := range targets {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(target.listGVK)
		selector := mergeStringMaps(gatewayLabels(), map[string]string{labelEgressRole: target.role})
		if err := s.reader.List(ctx, list, ctrlclient.InNamespace(s.egressRuntime.namespace), ctrlclient.MatchingLabels(selector)); err != nil {
			return nil, fmt.Errorf("list %s resources: %w", target.gvk.Kind, err)
		}
		for _, item := range list.Items {
			refs = append(refs, &egressv1.EgressResourceRef{
				Kind:      target.gvk.Kind,
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			})
		}
	}
	sortResourceRefs(refs)
	return refs, nil
}

func sortResourceRefs(refs []*egressv1.EgressResourceRef) {
	slices.SortFunc(refs, func(a, b *egressv1.EgressResourceRef) int {
		if a.GetKind() != b.GetKind() {
			return strings.Compare(a.GetKind(), b.GetKind())
		}
		if a.GetNamespace() != b.GetNamespace() {
			return strings.Compare(a.GetNamespace(), b.GetNamespace())
		}
		return strings.Compare(a.GetName(), b.GetName())
	})
}

func syncStatus(runtime egressRuntime, refs []*egressv1.EgressResourceRef) *egressv1.EgressSyncStatus {
	return &egressv1.EgressSyncStatus{
		Phase: egressv1.EgressSyncPhase_EGRESS_SYNC_PHASE_SYNCED,
		TargetGateway: &egressv1.EgressResourceRef{
			Kind:      "Gateway",
			Namespace: runtime.namespace,
			Name:      egressWaypointName,
		},
		AppliedResources: refs,
		LastSyncedAt:     timestamppb.Now(),
	}
}
