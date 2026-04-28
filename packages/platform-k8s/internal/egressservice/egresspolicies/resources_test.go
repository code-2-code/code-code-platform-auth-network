package egresspolicies

import (
	"testing"

	egressv1 "code-code.internal/go-contract/egress/v1"
	"code-code.internal/platform-k8s/internal/egressauthpolicy"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestDesiredObjectsDoNotSynthesizeRoutesForBaselineExternalAccess(t *testing.T) {
	objects := desiredObjects(egressRuntime{namespace: "code-code-net"}, desiredState{
		destinations: []*externalDestination{{
			destinationID:   "support.github-raw-content",
			displayName:     "GitHub Raw Content",
			host:            "raw.githubusercontent.com",
			port:            443,
			protocol:        egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
			resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
			serviceAccounts: []string{"code-code/platform-support-service"},
		}},
	})
	if got, want := len(objects), 2; got != want {
		t.Fatalf("objects = %d, want %d", got, want)
	}
	kinds := map[string]bool{}
	for _, obj := range objects {
		kinds[obj.GetObjectKind().GroupVersionKind().Kind] = true
	}
	if !kinds["ServiceEntry"] {
		t.Fatalf("generated kinds = %v, want ServiceEntry", kinds)
	}
	if !kinds["AuthorizationPolicy"] {
		t.Fatalf("generated kinds = %v, want AuthorizationPolicy", kinds)
	}
	for _, routeKind := range []string{"HTTPRoute", "TLSRoute", "TCPRoute"} {
		if kinds[routeKind] {
			t.Fatalf("generated kinds = %v, want no %s", kinds, routeKind)
		}
	}
}

func TestDesiredObjectsGroupsAuthorizationPoliciesBySourceAccounts(t *testing.T) {
	objects := desiredObjects(egressRuntime{namespace: "code-code-net"}, desiredState{
		destinations: []*externalDestination{
			{
				destinationID:   "models.github",
				displayName:     "GitHub Models",
				host:            "models.github.ai",
				port:            443,
				protocol:        egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
				resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
				serviceAccounts: []string{"code-code/platform-agent-runtime-service"},
			},
			{
				destinationID:   "api.openai",
				displayName:     "OpenAI API",
				host:            "api.openai.com",
				port:            443,
				protocol:        egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
				resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
				serviceAccounts: []string{"code-code/platform-agent-runtime-service"},
			},
			{
				destinationID:   "support.github-raw-content",
				displayName:     "GitHub Raw Content",
				host:            "raw.githubusercontent.com",
				port:            443,
				protocol:        egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
				resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
				serviceAccounts: []string{"code-code/platform-support-service"},
			},
		},
	})
	authPolicies := authorizationPolicies(objects)
	if got, want := len(authPolicies), 2; got != want {
		t.Fatalf("authorization policies = %d, want %d", got, want)
	}
	grouped := authPolicyWithTargetCount(t, authPolicies, 2)
	accounts := authorizationPolicyServiceAccounts(t, grouped)
	if got, want := accounts, []string{"code-code/platform-agent-runtime-service"}; !equalStringSlices(got, want) {
		t.Fatalf("serviceAccounts = %v, want %v", got, want)
	}
}

func TestDesiredObjectsGroupsDenyAllAuthorizationTargets(t *testing.T) {
	objects := desiredObjects(egressRuntime{namespace: "code-code-net"}, desiredState{
		destinations: []*externalDestination{
			{
				destinationID: "unclaimed-a",
				displayName:   "Unclaimed A",
				host:          "a.example.com",
				port:          443,
				protocol:      egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
				resolution:    egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
			},
			{
				destinationID: "unclaimed-b",
				displayName:   "Unclaimed B",
				host:          "b.example.com",
				port:          443,
				protocol:      egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
				resolution:    egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
			},
		},
	})
	authPolicies := authorizationPolicies(objects)
	if got, want := len(authPolicies), 1; got != want {
		t.Fatalf("authorization policies = %d, want %d", got, want)
	}
	policy := authPolicyWithTargetCount(t, authPolicies, 2)
	rules, ok, err := unstructured.NestedSlice(policy.Object, "spec", "rules")
	if err != nil || !ok {
		t.Fatalf("rules not found: ok=%v err=%v", ok, err)
	}
	if got, want := len(rules), 0; got != want {
		t.Fatalf("rules = %d, want %d", got, want)
	}
}

func TestDesiredObjectsSynthesizesOptInL7HTTPRoutes(t *testing.T) {
	destination := &externalDestination{
		destinationID:   "openai.api",
		displayName:     "OpenAI API",
		host:            "api.openai.com",
		port:            443,
		protocol:        egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS,
		resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
		serviceAccounts: []string{"code-code/platform-agent-runtime-service"},
	}
	objects := desiredObjects(egressRuntime{namespace: "code-code-net"}, desiredState{
		destinations: []*externalDestination{destination},
		httpRoutes: []*httpEgressRoute{{
			resourceID:  "support.openai-chat",
			routeID:     "openai-chat",
			displayName: "OpenAI chat headers",
			destination: destination,
			matches: []*httpRouteMatch{{
				pathPrefixes: []string{"/v1/chat/completions"},
				methods:      []string{"POST"},
			}},
			requestHeaders: headerPolicy{
				set:    []headerValue{{name: "X-Code-Code-Source", value: "agent-runtime"}},
				remove: []string{"X-Debug-Token"},
			},
			responseHeaders: headerPolicy{
				add: []headerValue{{name: "X-Code-Code-Egress", value: "l7"}},
			},
		}},
	})
	if got, want := len(objects), 8; got != want {
		t.Fatalf("objects = %d, want %d", got, want)
	}
	gateway := objectByName(t, objects, "Gateway", l7EgressGatewayName("openai.api"))
	gatewayOptions := objectByName(t, objects, "ConfigMap", l7EgressGatewayOptionsName("openai.api"))
	direct := objectByName(t, objects, "HTTPRoute", directHTTPRouteName("support.openai-chat"))
	forward := objectByName(t, objects, "HTTPRoute", forwardHTTPRouteName("support.openai-chat"))
	serviceEntry := objectByName(t, objects, "ServiceEntry", serviceEntryName("openai.api"))
	gatewayRule := objectByName(t, objects, "DestinationRule", gatewayDestinationRuleName("openai.api"))
	tlsOriginationRule := objectByName(t, objects, "DestinationRule", destinationRuleName("openai.api"))

	if _, ok := gateway.GetAnnotations()["networking.istio.io/service-type"]; ok {
		t.Fatalf("gateway has service-type annotation, want infrastructure parameters")
	}
	serviceOptions, ok, err := unstructured.NestedString(gatewayOptions.Object, "data", "service")
	if err != nil || !ok || serviceOptions != "spec:\n  type: ClusterIP" {
		t.Fatalf("gateway options service = %q ok=%v err=%v", serviceOptions, ok, err)
	}
	parameterRefName, ok, err := unstructured.NestedString(gateway.Object, "spec", "infrastructure", "parametersRef", "name")
	if err != nil || !ok || parameterRefName != l7EgressGatewayOptionsName("openai.api") {
		t.Fatalf("gateway parametersRef name = %q ok=%v err=%v", parameterRefName, ok, err)
	}

	listeners, ok, err := unstructured.NestedSlice(gateway.Object, "spec", "listeners")
	if err != nil || !ok || len(listeners) != 1 {
		t.Fatalf("gateway listeners not found: ok=%v len=%d err=%v", ok, len(listeners), err)
	}
	listener := listeners[0].(map[string]any)
	if got, want := listener["protocol"], "HTTPS"; got != want {
		t.Fatalf("gateway listener protocol = %v, want %v", got, want)
	}
	tls := listener["tls"].(map[string]any)
	if got, want := tls["mode"], "Terminate"; got != want {
		t.Fatalf("gateway tls mode = %v, want %v", got, want)
	}
	options := tls["options"].(map[string]any)
	if got, want := options["gateway.istio.io/tls-terminate-mode"], "ISTIO_MUTUAL"; got != want {
		t.Fatalf("gateway tls terminate mode = %v, want %v", got, want)
	}

	gatewayPortSettings, ok, err := unstructured.NestedSlice(gatewayRule.Object, "spec", "trafficPolicy", "portLevelSettings")
	if err != nil || !ok || len(gatewayPortSettings) != 1 {
		t.Fatalf("gateway destination rule port settings not found: ok=%v len=%d err=%v", ok, len(gatewayPortSettings), err)
	}
	gatewayTLS := gatewayPortSettings[0].(map[string]any)["tls"].(map[string]any)
	if got, want := gatewayTLS["mode"], "ISTIO_MUTUAL"; got != want {
		t.Fatalf("gateway destination rule tls mode = %v, want %v", got, want)
	}
	originPortSettings, ok, err := unstructured.NestedSlice(tlsOriginationRule.Object, "spec", "trafficPolicy", "portLevelSettings")
	if err != nil || !ok || len(originPortSettings) != 1 {
		t.Fatalf("tls origination port settings not found: ok=%v len=%d err=%v", ok, len(originPortSettings), err)
	}
	originTLS := originPortSettings[0].(map[string]any)["tls"].(map[string]any)
	if got, want := originTLS["caCertificates"], "system"; got != want {
		t.Fatalf("tls origination caCertificates = %v, want %v", got, want)
	}

	ports, ok, err := unstructured.NestedSlice(serviceEntry.Object, "spec", "ports")
	if err != nil || !ok || len(ports) != 2 {
		t.Fatalf("service entry ports not found: ok=%v len=%d err=%v", ok, len(ports), err)
	}
	if got, want := ports[0].(map[string]any)["protocol"], "HTTP"; got != want {
		t.Fatalf("service entry first port protocol = %v, want %v", got, want)
	}
	if got, want := ports[0].(map[string]any)["number"], int64(l7EgressClientHTTPPort); got != want {
		t.Fatalf("service entry first port number = %v, want %v", got, want)
	}
	if got, want := ports[1].(map[string]any)["protocol"], "HTTPS"; got != want {
		t.Fatalf("service entry second port protocol = %v, want %v", got, want)
	}

	parentRefs, ok, err := unstructured.NestedSlice(direct.Object, "spec", "parentRefs")
	if err != nil || !ok || len(parentRefs) != 1 {
		t.Fatalf("direct parentRefs not found: ok=%v len=%d err=%v", ok, len(parentRefs), err)
	}
	parentRef := parentRefs[0].(map[string]any)
	if got, want := parentRef["kind"], "ServiceEntry"; got != want {
		t.Fatalf("direct parent kind = %v, want %v", got, want)
	}
	rules, ok, err := unstructured.NestedSlice(direct.Object, "spec", "rules")
	if err != nil || !ok || len(rules) != 1 {
		t.Fatalf("direct rules not found: ok=%v len=%d err=%v", ok, len(rules), err)
	}
	backendRefs := rules[0].(map[string]any)["backendRefs"].([]any)
	backendRef := backendRefs[0].(map[string]any)
	if got, want := backendRef["name"], l7EgressGatewayServiceName("openai.api"); got != want {
		t.Fatalf("direct backend name = %v, want %v", got, want)
	}

	hostnames, ok, err := unstructured.NestedStringSlice(forward.Object, "spec", "hostnames")
	if err != nil || !ok {
		t.Fatalf("forward hostnames not found: ok=%v err=%v", ok, err)
	}
	if got, want := hostnames, []string{"api.openai.com"}; !equalStringSlices(got, want) {
		t.Fatalf("forward hostnames = %v, want %v", got, want)
	}
	rules, ok, err = unstructured.NestedSlice(forward.Object, "spec", "rules")
	if err != nil || !ok || len(rules) != 1 {
		t.Fatalf("forward rules not found: ok=%v len=%d err=%v", ok, len(rules), err)
	}
	forwardRule := rules[0].(map[string]any)
	filters := forwardRule["filters"].([]any)
	if got, want := filters[0].(map[string]any)["type"], "RequestHeaderModifier"; got != want {
		t.Fatalf("first filter type = %v, want %v", got, want)
	}
	backendRefs = forwardRule["backendRefs"].([]any)
	backendRef = backendRefs[0].(map[string]any)
	if got, want := backendRef["kind"], "Hostname"; got != want {
		t.Fatalf("forward backend kind = %v, want %v", got, want)
	}
	if got, want := backendRef["name"], "api.openai.com"; got != want {
		t.Fatalf("forward backend name = %v, want %v", got, want)
	}
}

func TestDesiredObjectsSynthesizesRouteScopedDynamicHeaderAuthz(t *testing.T) {
	destination := &externalDestination{
		destinationID:   "openai.api",
		displayName:     "OpenAI API",
		host:            "api.openai.com",
		port:            443,
		protocol:        egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS,
		resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
		serviceAccounts: []string{"code-code/platform-agent-runtime-service"},
	}
	objects := desiredObjects(egressRuntime{
		namespace:                      "code-code-net",
		dynamicHeaderAuthzProviderName: egressauthpolicy.BearerExtensionProviderName,
	}, desiredState{
		destinations: []*externalDestination{destination},
		httpRoutes: []*httpEgressRoute{{
			resourceID:         "support.openai-chat",
			routeID:            "openai-chat",
			displayName:        "OpenAI chat headers",
			destination:        destination,
			dynamicHeaderAuthz: true,
			matches: []*httpRouteMatch{{
				pathPrefixes: []string{"/v1/chat/completions"},
				methods:      []string{"POST"},
			}},
		}},
	})
	if got, want := len(objects), 9; got != want {
		t.Fatalf("objects = %d, want %d", got, want)
	}
	policy := objectByName(t, objects, "AuthorizationPolicy", dynamicHeaderAuthzPolicyName(egressauthpolicy.BearerExtensionProviderName))
	if got, ok, err := unstructured.NestedString(policy.Object, "spec", "action"); err != nil || !ok || got != "CUSTOM" {
		t.Fatalf("action = %q ok=%v err=%v, want CUSTOM", got, ok, err)
	}
	if got, ok, err := unstructured.NestedString(policy.Object, "spec", "provider", "name"); err != nil || !ok || got != egressauthpolicy.BearerExtensionProviderName {
		t.Fatalf("provider name = %q ok=%v err=%v, want %s", got, ok, err, egressauthpolicy.BearerExtensionProviderName)
	}
	targetRefs, ok, err := unstructured.NestedSlice(policy.Object, "spec", "targetRefs")
	if err != nil || !ok || len(targetRefs) != 1 {
		t.Fatalf("targetRefs not found: ok=%v len=%d err=%v", ok, len(targetRefs), err)
	}
	targetRef := targetRefs[0].(map[string]any)
	if got, want := targetRef["kind"], "ServiceEntry"; got != want {
		t.Fatalf("targetRef kind = %v, want %v", got, want)
	}
	if got, want := targetRef["name"], serviceEntryName("openai.api"); got != want {
		t.Fatalf("targetRef name = %v, want %v", got, want)
	}
	rules, ok, err := unstructured.NestedSlice(policy.Object, "spec", "rules")
	if err != nil || !ok || len(rules) != 1 {
		t.Fatalf("rules not found: ok=%v len=%d err=%v", ok, len(rules), err)
	}
	to := rules[0].(map[string]any)["to"].([]any)
	operation := to[0].(map[string]any)["operation"].(map[string]any)
	if got, want := stringListFromAny(t, operation["hosts"]), []string{"api.openai.com"}; !equalStringSlices(got, want) {
		t.Fatalf("operation hosts = %v, want %v", got, want)
	}
	if got, want := stringListFromAny(t, operation["methods"]), []string{"POST"}; !equalStringSlices(got, want) {
		t.Fatalf("operation methods = %v, want %v", got, want)
	}
	if got, want := stringListFromAny(t, operation["paths"]), []string{"/v1/chat/completions*"}; !equalStringSlices(got, want) {
		t.Fatalf("operation paths = %v, want %v", got, want)
	}
}

func authorizationPolicies(objects []ctrlclient.Object) []*unstructured.Unstructured {
	out := make([]*unstructured.Unstructured, 0)
	for _, obj := range objects {
		if obj.GetObjectKind().GroupVersionKind().Kind != "AuthorizationPolicy" {
			continue
		}
		policy, ok := obj.(*unstructured.Unstructured)
		if ok {
			out = append(out, policy)
		}
	}
	return out
}

func objectByName(t *testing.T, objects []ctrlclient.Object, kind string, name string) *unstructured.Unstructured {
	t.Helper()
	for _, obj := range objects {
		if obj.GetObjectKind().GroupVersionKind().Kind != kind || obj.GetName() != name {
			continue
		}
		unstructuredObj, ok := obj.(*unstructured.Unstructured)
		if !ok {
			t.Fatalf("%s/%s has type %T, want *unstructured.Unstructured", kind, name, obj)
		}
		return unstructuredObj
	}
	t.Fatalf("%s/%s not found", kind, name)
	return nil
}

func authPolicyWithTargetCount(t *testing.T, policies []*unstructured.Unstructured, count int) *unstructured.Unstructured {
	t.Helper()
	for _, policy := range policies {
		targetRefs, ok, err := unstructured.NestedSlice(policy.Object, "spec", "targetRefs")
		if err != nil {
			t.Fatalf("targetRefs error = %v", err)
		}
		if ok && len(targetRefs) == count {
			return policy
		}
	}
	t.Fatalf("no AuthorizationPolicy with %d targetRefs found", count)
	return nil
}

func authorizationPolicyServiceAccounts(t *testing.T, policy *unstructured.Unstructured) []string {
	t.Helper()
	rules, ok, err := unstructured.NestedSlice(policy.Object, "spec", "rules")
	if err != nil || !ok || len(rules) != 1 {
		t.Fatalf("rules not found: ok=%v len=%d err=%v", ok, len(rules), err)
	}
	rule, ok := rules[0].(map[string]any)
	if !ok {
		t.Fatalf("rule has type %T, want map", rules[0])
	}
	from, ok := rule["from"].([]any)
	if !ok || len(from) != 1 {
		t.Fatalf("from = %#v, want one item", rule["from"])
	}
	fromItem, ok := from[0].(map[string]any)
	if !ok {
		t.Fatalf("from item has type %T, want map", from[0])
	}
	source, ok := fromItem["source"].(map[string]any)
	if !ok {
		t.Fatalf("source = %#v, want map", fromItem["source"])
	}
	rawAccounts, ok := source["serviceAccounts"].([]any)
	if !ok {
		t.Fatalf("serviceAccounts = %#v, want list", source["serviceAccounts"])
	}
	accounts := make([]string, 0, len(rawAccounts))
	for _, account := range rawAccounts {
		value, ok := account.(string)
		if !ok {
			t.Fatalf("service account has type %T, want string", account)
		}
		accounts = append(accounts, value)
	}
	return accounts
}

func stringListFromAny(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("value = %#v, want []any", value)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("list item = %#v, want string", item)
		}
		out = append(out, text)
	}
	return out
}
