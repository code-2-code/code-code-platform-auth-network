package egresspolicies

import "strings"

func resourceLabels(role string, destination *externalDestination) map[string]string {
	return mergeStringMaps(gatewayLabels(), map[string]string{
		labelEgressRole:        role,
		labelEgressDestination: destinationLabelValue(destination.destinationID),
	})
}

func serviceEntryGroupLabels(role string, group *serviceEntryGroup) map[string]string {
	return mergeStringMaps(gatewayLabels(), map[string]string{
		labelEgressRole:        role,
		labelEgressDestination: destinationLabelValue(group.groupID),
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

func httpRouteLabels(role string, rule *httpInspectionRule) map[string]string {
	return mergeStringMaps(resourceLabels(role, rule.destination), map[string]string{
		labelEgressRoute: destinationLabelValue(rule.resourceID),
	})
}

func destinationRouteLabels(role string, destination *externalDestination) map[string]string {
	return mergeStringMaps(resourceLabels(role, destination), map[string]string{
		labelEgressRoute: destinationLabelValue(destination.destinationID),
	})
}

func proxyEndpointLabels(role string, endpoint *proxyEndpoint) map[string]string {
	return mergeStringMaps(gatewayLabels(), map[string]string{
		labelEgressRole:          role,
		labelEgressProxyEndpoint: destinationLabelValue(endpoint.proxyEndpointID),
	})
}

func forwarderLabels(role string, group *proxyEndpointDestinationGroup) map[string]string {
	routeID := group.routeID
	if routeID == "" {
		routeID = group.proxyEndpoint.proxyEndpointID
	}
	return mergeStringMaps(proxyEndpointLabels(role, group.proxyEndpoint), map[string]string{
		labelEgressRoute: destinationLabelValue(routeID),
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

func serviceEntryGroupAnnotations(group *serviceEntryGroup) map[string]string {
	displayName := "External destinations"
	if len(group.destinations) == 1 {
		displayName = group.destinations[0].displayName
	}
	return map[string]string{
		annotationDisplayName:   displayName,
		annotationDestinationID: strings.Join(serviceEntryGroupDestinationIDs(group), ","),
		annotationOwnerService:  strings.Join(group.ownerServices, ","),
		labelEgressAccessSetID:  strings.Join(group.accessSetIDs, ","),
	}
}

func proxyEndpointAnnotations(endpoint *proxyEndpoint) map[string]string {
	return map[string]string{
		annotationDisplayName:  endpoint.displayName,
		annotationOwnerService: strings.Join(endpoint.ownerServices, ","),
		labelEgressAccessSetID: strings.Join(endpoint.accessSetIDs, ","),
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

func dynamicHeaderAuthzAnnotations(providerName string, routes []*httpInspectionRule) map[string]string {
	return map[string]string{
		annotationDisplayName:   "Dynamic header authorization for " + providerName,
		annotationDestinationID: strings.Join(dynamicHeaderAuthzDestinationIDs(routes), ","),
		annotationOwnerService:  strings.Join(dynamicHeaderAuthzOwnerServices(routes), ","),
		labelEgressAccessSetID:  strings.Join(dynamicHeaderAuthzAccessSetIDs(routes), ","),
	}
}

func httpRouteAnnotations(route *httpInspectionRule) map[string]string {
	annotations := map[string]string{
		annotationDisplayName:                 route.displayName,
		annotationDestinationID:               route.destination.destinationID,
		annotationOwnerService:                strings.Join(route.ownerServices, ","),
		labelEgressAccessSetID:                strings.Join(route.accessSetIDs, ","),
		labelEgressRoute:                      route.inspectionRuleID,
		egressLabelPrefix + "/auth-policy-id": strings.TrimSpace(route.authPolicyID),
	}
	return annotations
}

func proxyForwarderAnnotations(group *proxyEndpointDestinationGroup) map[string]string {
	routeID := group.routeID
	if routeID == "" {
		routeID = group.proxyEndpoint.proxyEndpointID
	}
	return map[string]string{
		annotationDisplayName:                    group.proxyEndpoint.displayName + " egress forwarder",
		annotationDestinationID:                  strings.Join(proxyGroupDestinationIDs(group.destinations), ","),
		annotationOwnerService:                   strings.Join(group.ownerServices, ","),
		labelEgressAccessSetID:                   strings.Join(group.accessSetIDs, ","),
		labelEgressRoute:                         routeID,
		egressLabelPrefix + "/proxy-endpoint-id": group.proxyEndpoint.proxyEndpointID,
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

func proxyGroupDestinationIDs(destinations []*externalDestination) []string {
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

func dynamicHeaderAuthzDestinationIDs(routes []*httpInspectionRule) []string {
	out := make([]string, 0, len(routes))
	for _, route := range routes {
		out = append(out, route.destination.destinationID)
	}
	return mergeValues(nil, out)
}

func dynamicHeaderAuthzOwnerServices(routes []*httpInspectionRule) []string {
	var out []string
	for _, route := range routes {
		out = mergeValues(out, route.ownerServices)
	}
	return out
}

func dynamicHeaderAuthzAccessSetIDs(routes []*httpInspectionRule) []string {
	var out []string
	for _, route := range routes {
		out = mergeValues(out, route.accessSetIDs)
	}
	return out
}
