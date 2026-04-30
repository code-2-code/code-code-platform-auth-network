package egresspolicies

import (
	"fmt"
	"slices"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
)

type serviceEntryGroup struct {
	groupID         string
	destinations    []*externalDestination
	serviceAccounts []string
	ownerServices   []string
	accessSetIDs    []string
}

func groupedServiceEntries(destinations []*externalDestination, l7Destinations []*externalDestination) []*serviceEntryGroup {
	l7DestinationIDs := destinationIDSet(l7Destinations)
	groupsByKey := map[string]*serviceEntryGroup{}
	for _, destination := range destinations {
		destination.serviceEntry = nil
		key := serviceEntryGroupKey(destination, l7DestinationIDs)
		group, ok := groupsByKey[key]
		if !ok {
			group = &serviceEntryGroup{}
			groupsByKey[key] = group
		}
		group.destinations = append(group.destinations, destination)
		group.serviceAccounts = mergeValues(group.serviceAccounts, destination.serviceAccounts)
		group.ownerServices = mergeValues(group.ownerServices, destination.ownerServices)
		group.accessSetIDs = mergeValues(group.accessSetIDs, destination.accessSetIDs)
	}
	groups := make([]*serviceEntryGroup, 0, len(groupsByKey))
	for _, group := range groupsByKey {
		slices.SortFunc(group.destinations, func(a, b *externalDestination) int {
			return strings.Compare(a.destinationID, b.destinationID)
		})
		group.groupID = serviceEntryGroupID(group)
		for _, destination := range group.destinations {
			destination.serviceEntry = group
		}
		groups = append(groups, group)
	}
	slices.SortFunc(groups, func(a, b *serviceEntryGroup) int {
		return strings.Compare(a.groupID, b.groupID)
	})
	return groups
}

func serviceEntryGroupKey(destination *externalDestination, l7DestinationIDs map[string]struct{}) string {
	if _, ok := l7DestinationIDs[destination.destinationID]; ok {
		return "single:" + destination.destinationID
	}
	if destination.addressCidr != "" || strings.HasPrefix(destination.host, "*.") {
		return "single:" + destination.destinationID
	}
	parts := []string{
		"group",
		protocolString(destination.protocol),
		fmt.Sprint(destination.port),
		resolutionString(destination.resolution),
		destination.proxyEndpointID,
		authorizationGroupKey(mergeValues(nil, destination.serviceAccounts)),
	}
	return strings.Join(parts, "|")
}

func serviceEntryGroupID(group *serviceEntryGroup) string {
	if len(group.destinations) == 1 {
		return group.destinations[0].destinationID
	}
	first := group.destinations[0]
	return strings.ToLower(protocolString(first.protocol)) + "-" + fmt.Sprint(first.port) + "-" + shortHash(strings.Join(serviceEntryGroupDestinationIDs(group), ","))
}

func serviceEntryNameForDestination(destination *externalDestination) string {
	if destination.serviceEntry != nil {
		return serviceEntryName(destination.serviceEntry.groupID)
	}
	return serviceEntryName(destination.destinationID)
}

func serviceEntryGroupHosts(group *serviceEntryGroup) []any {
	hosts := make([]any, 0, len(group.destinations))
	for _, destination := range group.destinations {
		hosts = append(hosts, destination.host)
	}
	return hosts
}

func serviceEntryGroupDestinationIDs(group *serviceEntryGroup) []string {
	out := make([]string, 0, len(group.destinations))
	for _, destination := range group.destinations {
		out = append(out, destination.destinationID)
	}
	return mergeValues(nil, out)
}

func destinationIDSet(destinations []*externalDestination) map[string]struct{} {
	out := make(map[string]struct{}, len(destinations))
	for _, destination := range destinations {
		out[destination.destinationID] = struct{}{}
	}
	return out
}

func groupAddressCidr(group *serviceEntryGroup) string {
	if len(group.destinations) != 1 {
		return ""
	}
	return group.destinations[0].addressCidr
}

func groupPrimaryDestination(group *serviceEntryGroup) *externalDestination {
	if len(group.destinations) == 0 {
		return nil
	}
	return group.destinations[0]
}

func serviceEntryGroupPorts(group *serviceEntryGroup) []any {
	destination := groupPrimaryDestination(group)
	if destination == nil {
		return nil
	}
	return serviceEntryPorts(destination)
}

func serviceEntryGroupResolution(group *serviceEntryGroup) string {
	destination := groupPrimaryDestination(group)
	if destination == nil {
		return resolutionString(egressv1.EgressResolution_EGRESS_RESOLUTION_DNS)
	}
	return resolutionString(destination.resolution)
}
