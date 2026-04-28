package egresspolicies

const (
	policyID          = "code-code-egress"
	policyDisplayName = "Istio Ambient Egress"
	fieldOwner        = "platform-egress-service"

	policyConfigMapName = "code-code-egress-policy"
	policyConfigKey     = "egress-policy.json"

	egressWaypointName     = "egress-waypoint"
	l7EgressClientHTTPPort = 80

	resourcePrefixServiceEntry     = "code-code-egress-dst"
	resourcePrefixAuthz            = "code-code-egress-authz"
	resourcePrefixL7Gateway        = "code-code-egress-gw"
	resourcePrefixL7GatewayOptions = "code-code-egress-gw-options"
	resourcePrefixGatewayMTLS      = "code-code-egress-gw-mtls"
	resourceNameDynamicHeaderAuthz = "code-code-egress-dynamic-header-authz"
	resourcePrefixDirectHTTPRoute  = "code-code-egress-to-gw"
	resourcePrefixForwardHTTPRoute = "code-code-egress-from-gw"
	resourcePrefixDestinationRule  = "code-code-egress-tls"

	egressLabelPrefix          = "egress.platform.code-code.internal"
	labelEgressRole            = egressLabelPrefix + "/role"
	labelEgressDestination     = egressLabelPrefix + "/destination"
	labelEgressRoute           = egressLabelPrefix + "/route"
	labelEgressAccessSetID     = egressLabelPrefix + "/access-set-id"
	annotationDisplayName      = egressLabelPrefix + "/display-name"
	annotationDestinationID    = egressLabelPrefix + "/destination-id"
	annotationOwnerService     = egressLabelPrefix + "/owner-service"
	egressRolePolicy           = "policy"
	egressRoleDestination      = "external-destination"
	egressRoleAuthorization    = "authorization"
	egressRoleL7Gateway        = "l7-egress-gateway"
	egressRoleL7GatewayOptions = "l7-egress-gateway-options"
	egressRoleGatewayMTLS      = "gateway-mtls"
	egressRoleDirectHTTPRoute  = "direct-http-route"
	egressRoleForwardHTTPRoute = "forward-http-route"
	egressRoleTLSOrigination   = "tls-origination"
	egressRoleDynamicAuthz     = "dynamic-header-authz"
)

func gatewayLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "code-code-egress",
		"app.kubernetes.io/component":  "egress-policy",
		"app.kubernetes.io/part-of":    "code-code",
		"app.kubernetes.io/managed-by": fieldOwner,
	}
}

func mergeStringMaps(base map[string]string, overlays ...map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range base {
		out[key] = value
	}
	for _, overlay := range overlays {
		for key, value := range overlay {
			if value != "" {
				out[key] = value
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
