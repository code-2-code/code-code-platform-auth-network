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
	tlsRouteGVK     = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1alpha3", Kind: "TLSRoute"}
	tlsRouteListGVK = schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1alpha3",
		Kind:    "TLSRouteList",
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
	deploymentGVK     = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	deploymentListGVK = schema.GroupVersionKind{
		Group:   "apps",
		Version: "v1",
		Kind:    "DeploymentList",
	}
	serviceGVK     = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Service"}
	serviceListGVK = schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "ServiceList",
	}
	serviceAccountGVK     = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ServiceAccount"}
	serviceAccountListGVK = schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "ServiceAccountList",
	}
	networkPolicyGVK     = schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}
	networkPolicyListGVK = schema.GroupVersionKind{
		Group:   "networking.k8s.io",
		Version: "v1",
		Kind:    "NetworkPolicyList",
	}
	authorizationPolicyGVK     = schema.GroupVersionKind{Group: "security.istio.io", Version: "v1", Kind: "AuthorizationPolicy"}
	authorizationPolicyListGVK = schema.GroupVersionKind{
		Group:   "security.istio.io",
		Version: "v1",
		Kind:    "AuthorizationPolicyList",
	}
)

func desiredObjects(runtime egressRuntime, desired desiredState) []ctrlclient.Object {
	l7Destinations := l7EgressDestinations(desired.httpInspectionRules)
	serviceEntryGroups := groupedServiceEntries(desired.destinations, l7Destinations)
	authorizationGroups := groupedAuthorizations(desired.destinations)
	dynamicAuthzRoutes := dynamicHeaderAuthzRoutes(desired.httpInspectionRules)
	dynamicAuthzGroups := dynamicHeaderAuthzRouteGroups(runtime, dynamicAuthzRoutes)
	directDestinations := directL7EgressDestinations(desired.httpInspectionRules)
	proxyDestinationGroups := proxyEndpointDestinationGroups(desired.destinations)
	capacity := len(serviceEntryGroups) + len(desired.proxyEndpoints) + len(authorizationGroups) + len(desired.httpInspectionRules)*2 + len(l7Destinations)*3 + len(directDestinations)
	capacity += len(proxyDestinationGroups)*5 + 2
	capacity += len(dynamicAuthzGroups)
	objects := make([]ctrlclient.Object, 0, capacity)
	for _, group := range serviceEntryGroups {
		objects = append(objects, serviceEntryObject(runtime, group))
	}
	for _, endpoint := range desired.proxyEndpoints {
		objects = append(objects, proxyEndpointServiceEntryObject(runtime, endpoint))
	}
	for _, group := range authorizationGroups {
		objects = append(objects, authorizationPolicyObject(runtime, group))
	}
	if len(desired.proxyEndpoints) > 0 {
		objects = append(objects, forwarderServiceAccountObject(runtime))
		objects = append(objects, proxyEndpointAuthorizationPolicyObject(runtime, desired.proxyEndpoints))
	}
	for _, group := range dynamicAuthzGroups {
		objects = append(objects, dynamicHeaderAuthzPolicyObject(runtime, group))
	}
	for _, destination := range l7Destinations {
		objects = append(objects, l7EgressGatewayOptionsObject(runtime, destination))
		objects = append(objects, l7EgressGatewayObject(runtime, destination))
		objects = append(objects, egressGatewayDestinationRuleObject(runtime, destination))
	}
	for _, rule := range desired.httpInspectionRules {
		objects = append(objects, directHTTPRouteObject(runtime, rule))
		objects = append(objects, forwardHTTPRouteObject(runtime, rule))
	}
	for _, group := range proxyDestinationGroups {
		for _, routeGroup := range proxyEndpointTLSRouteGroups(group) {
			objects = append(objects, proxyEndpointTLSRouteObject(runtime, routeGroup))
		}
		objects = append(objects, forwarderConfigObject(runtime, group))
		objects = append(objects, forwarderDeploymentObject(runtime, group))
		objects = append(objects, forwarderServiceObject(runtime, group))
		objects = append(objects, forwarderNetworkPolicyObject(runtime, group))
	}
	for _, destination := range directDestinations {
		objects = append(objects, tlsOriginationDestinationRuleObject(runtime, destination))
	}
	return objects
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
	targets := managedResourceTypes()
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

func managedResourceTypes() []managedResourceType {
	return []managedResourceType{
		{gvk: serviceEntryGVK, listGVK: serviceEntryListGVK, role: egressRoleDestination},
		{gvk: serviceEntryGVK, listGVK: serviceEntryListGVK, role: egressRoleProxyEndpoint},
		{gvk: authorizationPolicyGVK, listGVK: authorizationPolicyListGVK, role: egressRoleAuthorization},
		{gvk: authorizationPolicyGVK, listGVK: authorizationPolicyListGVK, role: egressRoleProxyAuthz},
		{gvk: authorizationPolicyGVK, listGVK: authorizationPolicyListGVK, role: egressRoleDynamicAuthz},
		{gvk: configMapGVK, listGVK: configMapListGVK, role: egressRoleL7GatewayOptions},
		{gvk: gatewayGVK, listGVK: gatewayListGVK, role: egressRoleL7Gateway},
		{gvk: configMapGVK, listGVK: configMapListGVK, role: egressRoleTLSGatewayOptions},
		{gvk: gatewayGVK, listGVK: gatewayListGVK, role: egressRoleTLSGateway},
		{gvk: destinationRuleGVK, listGVK: destinationRuleListGVK, role: egressRoleGatewayMTLS},
		{gvk: httpRouteGVK, listGVK: httpRouteListGVK, role: egressRoleDirectHTTPRoute},
		{gvk: httpRouteGVK, listGVK: httpRouteListGVK, role: egressRoleForwardHTTPRoute},
		{gvk: tlsRouteGVK, listGVK: tlsRouteListGVK, role: egressRoleDirectTLSRoute},
		{gvk: tlsRouteGVK, listGVK: tlsRouteListGVK, role: egressRoleForwardTLSRoute},
		{gvk: destinationRuleGVK, listGVK: destinationRuleListGVK, role: egressRoleTLSOrigination},
		{gvk: configMapGVK, listGVK: configMapListGVK, role: egressRoleForwarderConfig},
		{gvk: serviceAccountGVK, listGVK: serviceAccountListGVK, role: egressRoleForwarderSA},
		{gvk: deploymentGVK, listGVK: deploymentListGVK, role: egressRoleForwarder},
		{gvk: serviceGVK, listGVK: serviceListGVK, role: egressRoleForwarder},
		{gvk: destinationRuleGVK, listGVK: destinationRuleListGVK, role: egressRoleForwarderTLS},
		{gvk: networkPolicyGVK, listGVK: networkPolicyListGVK, role: egressRoleForwarderNetpol},
	}
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
	targets := managedResourceTypes()
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
