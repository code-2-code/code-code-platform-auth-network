package egresspolicies

import (
	"fmt"
	"strings"
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
	grouped := authPolicyWithServiceAccount(t, authPolicies, "code-code/platform-agent-runtime-service")
	accounts := authorizationPolicyServiceAccounts(t, grouped)
	if got, want := accounts, []string{"code-code/platform-agent-runtime-service"}; !equalStringSlices(got, want) {
		t.Fatalf("serviceAccounts = %v, want %v", got, want)
	}
	targetNames := authorizationPolicyTargetNames(t, grouped)
	if got, want := len(targetNames), 1; got != want {
		t.Fatalf("targetRefs = %d, want %d", got, want)
	}
	groupedServiceEntry := objectByName(t, objects, "ServiceEntry", targetNames[0])
	if got, want := serviceEntryHosts(t, groupedServiceEntry), []string{"api.openai.com", "models.github.ai"}; !equalStringSlices(got, want) {
		t.Fatalf("grouped ServiceEntry hosts = %v, want %v", got, want)
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
	policy := authPolicyWithTargetCount(t, authPolicies, 1)
	targetNames := authorizationPolicyTargetNames(t, policy)
	groupedServiceEntry := objectByName(t, objects, "ServiceEntry", targetNames[0])
	if got, want := serviceEntryHosts(t, groupedServiceEntry), []string{"a.example.com", "b.example.com"}; !equalStringSlices(got, want) {
		t.Fatalf("deny-all ServiceEntry hosts = %v, want %v", got, want)
	}
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
		httpInspectionRules: []*httpInspectionRule{{
			resourceID:       "support.openai-chat",
			inspectionRuleID: "openai-chat",
			displayName:      "OpenAI chat headers",
			destination:      destination,
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

func TestDesiredObjectsDoesNotAttachProxyToL7InspectionRule(t *testing.T) {
	destination := &externalDestination{
		destinationID:   "google.aistudio.rpc",
		displayName:     "Google AI Studio RPC",
		host:            "alkalimakersuite-pa.clients6.google.com",
		port:            443,
		protocol:        egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS,
		resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
		serviceAccounts: []string{"code-code/platform-provider-service"},
	}
	proxy := &proxyEndpoint{
		proxyEndpointID: "preset-proxy",
		displayName:     "Preset Proxy",
		host:            "preset-proxy.local",
		addressCidr:     "192.168.0.126/32",
		port:            10809,
		protocol:        egressv1.ProxyProtocol_PROXY_PROTOCOL_HTTP_CONNECT,
		resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_NONE,
	}
	objects := desiredObjects(egressRuntime{
		namespace:      "code-code-net",
		forwarderImage: "registry.local/code-code/platform-egress-forwarder:test",
	}, desiredState{
		destinations:   []*externalDestination{destination},
		proxyEndpoints: []*proxyEndpoint{proxy},
		httpInspectionRules: []*httpInspectionRule{{
			resourceID:       "support.google-aistudio-rpc",
			inspectionRuleID: "google-aistudio-rpc",
			displayName:      "Google AI Studio RPC headers",
			destination:      destination,
			matches: []*httpRouteMatch{{
				pathPrefixes: []string{"/$rpc/google.internal.alkali.applications.makersuite.v1.MakerSuiteService/"},
				methods:      []string{"POST"},
			}},
		}},
	})
	if objectExists(objects, "ConfigMap", forwarderConfigName("support.google-aistudio-rpc")) {
		t.Fatal("forwarder generated for L7 inspection rule; L7 rules must not carry proxy endpoints")
	}
	forward := objectByName(t, objects, "HTTPRoute", forwardHTTPRouteName("support.google-aistudio-rpc"))
	rules, ok, err := unstructured.NestedSlice(forward.Object, "spec", "rules")
	if err != nil || !ok || len(rules) != 1 {
		t.Fatalf("forward rules not found: ok=%v len=%d err=%v", ok, len(rules), err)
	}
	backendRefs := rules[0].(map[string]any)["backendRefs"].([]any)
	backendRef := backendRefs[0].(map[string]any)
	if got, want := backendRef["kind"], "Hostname"; got != want {
		t.Fatalf("forward backend kind = %v, want %v", got, want)
	}
}

func TestDesiredObjectsSynthesizesSharedProxyForwarderForTLSPassthroughDestinations(t *testing.T) {
	mistral := &externalDestination{
		destinationID:   "mistral.api",
		displayName:     "Mistral API",
		host:            "api.mistral.ai",
		port:            443,
		protocol:        egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
		resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
		serviceAccounts: []string{"code-code/provider-host-blackbox-exporter"},
	}
	openrouter := &externalDestination{
		destinationID:   "openrouter.catalog",
		displayName:     "OpenRouter Catalog",
		host:            "openrouter.ai",
		port:            443,
		protocol:        egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
		resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
		serviceAccounts: []string{"code-code/provider-host-blackbox-exporter"},
	}
	proxy := &proxyEndpoint{
		proxyEndpointID: "preset-proxy",
		displayName:     "Preset Proxy",
		host:            "preset-proxy.local",
		addressCidr:     "192.168.0.126/32",
		port:            10809,
		protocol:        egressv1.ProxyProtocol_PROXY_PROTOCOL_HTTP_CONNECT,
		resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_NONE,
	}
	for _, destination := range []*externalDestination{mistral, openrouter} {
		destination.proxyEndpointID = proxy.proxyEndpointID
		destination.proxyEndpoint = proxy
	}
	objects := desiredObjects(egressRuntime{
		namespace:      "code-code-net",
		forwarderImage: "registry.local/code-code/platform-egress-forwarder:test",
	}, desiredState{
		destinations:   []*externalDestination{mistral, openrouter},
		proxyEndpoints: []*proxyEndpoint{proxy},
	})
	if got, want := len(objects), 10; got != want {
		t.Fatalf("objects = %d, want %d", got, want)
	}
	if objectExists(objects, "Gateway", tlsEgressGatewayName("mistral.api")) {
		t.Fatal("per-destination TLS gateway generated for proxied TLS destination")
	}
	if objectExists(objects, "Gateway", tlsEgressGatewayName("openrouter.catalog")) {
		t.Fatal("per-destination TLS gateway generated for second proxied TLS destination")
	}
	route := objectByName(t, objects, "TLSRoute", proxyEndpointTLSRouteName("preset-proxy"))
	hostnames, ok, err := unstructured.NestedStringSlice(route.Object, "spec", "hostnames")
	if err != nil || !ok {
		t.Fatalf("proxy tls hostnames not found: ok=%v err=%v", ok, err)
	}
	if got, want := hostnames, []string{"api.mistral.ai", "openrouter.ai"}; !equalStringSlices(got, want) {
		t.Fatalf("proxy tls hostnames = %v, want %v", got, want)
	}
	parentRefs, ok, err := unstructured.NestedSlice(route.Object, "spec", "parentRefs")
	if err != nil || !ok || len(parentRefs) != 1 {
		t.Fatalf("proxy tls parentRefs not found: ok=%v len=%d err=%v", ok, len(parentRefs), err)
	}
	parentName := parentRefs[0].(map[string]any)["name"].(string)
	groupedServiceEntry := objectByName(t, objects, "ServiceEntry", parentName)
	if got, want := serviceEntryHosts(t, groupedServiceEntry), []string{"api.mistral.ai", "openrouter.ai"}; !equalStringSlices(got, want) {
		t.Fatalf("proxy ServiceEntry hosts = %v, want %v", got, want)
	}
	rules, ok, err := unstructured.NestedSlice(route.Object, "spec", "rules")
	if err != nil || !ok || len(rules) != 1 {
		t.Fatalf("proxy tls rules not found: ok=%v len=%d err=%v", ok, len(rules), err)
	}
	backendRefs := rules[0].(map[string]any)["backendRefs"].([]any)
	backendRef := backendRefs[0].(map[string]any)
	if _, ok := backendRef["kind"]; ok {
		t.Fatalf("proxy tls backend kind = %v, want Kubernetes Service backend", backendRef["kind"])
	}
	if got, want := backendRef["name"], forwarderName("preset-proxy"); got != want {
		t.Fatalf("proxy tls backend name = %v, want %v", got, want)
	}
	if got, want := backendRef["port"], int64(egressForwarderPort); got != want {
		t.Fatalf("proxy tls backend port = %v, want %v", got, want)
	}

	config := objectByName(t, objects, "ConfigMap", forwarderConfigName("preset-proxy"))
	configYAML, ok, err := unstructured.NestedString(config.Object, "data", "config.yaml")
	if err != nil || !ok {
		t.Fatalf("forwarder config not found: ok=%v err=%v", ok, err)
	}
	for _, want := range []string{
		`type: sni`,
		`addr: "192.168.0.126:10809"`,
		`type: "http"`,
	} {
		if !strings.Contains(configYAML, want) {
			t.Fatalf("forwarder config does not contain %q:\n%s", want, configYAML)
		}
	}
	if strings.Contains(configYAML, `api.mistral.ai:443`) || strings.Contains(configYAML, `openrouter.ai:443`) {
		t.Fatalf("forwarder config contains destination-specific target:\n%s", configYAML)
	}
	deployment := objectByName(t, objects, "Deployment", forwarderName("preset-proxy"))
	containers, ok, err := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "containers")
	if err != nil || !ok || len(containers) != 1 {
		t.Fatalf("containers not found: ok=%v len=%d err=%v", ok, len(containers), err)
	}
	container := containers[0].(map[string]any)
	if got, want := container["image"], "registry.local/code-code/platform-egress-forwarder:test"; got != want {
		t.Fatalf("forwarder image = %v, want %v", got, want)
	}
	networkPolicy := objectByName(t, objects, "NetworkPolicy", forwarderNetworkPolicyName("preset-proxy"))
	ingress, ok, err := unstructured.NestedSlice(networkPolicy.Object, "spec", "ingress")
	if err != nil || !ok || len(ingress) != 1 {
		t.Fatalf("network policy ingress not found: ok=%v len=%d err=%v", ok, len(ingress), err)
	}
	from := ingress[0].(map[string]any)["from"].([]any)
	podSelector := from[0].(map[string]any)["podSelector"].(map[string]any)
	matchLabels := podSelector["matchLabels"].(map[string]any)
	if got, want := matchLabels["gateway.networking.k8s.io/gateway-name"], egressWaypointName; got != want {
		t.Fatalf("network policy ingress gateway label = %v, want %v", got, want)
	}
	if objectExists(objects, "DestinationRule", forwarderTLSRuleName("preset-proxy")) {
		t.Fatal("forwarder TLS origination destination rule generated for TLS passthrough route")
	}
	if objectExists(objects, "HTTPRoute", directHTTPRouteName("mistral.api")) {
		t.Fatal("HTTPRoute generated for TLS passthrough destination")
	}
}

func TestDesiredObjectsChunksProxyEndpointTLSRoutesByGatewayAPIHostnameLimit(t *testing.T) {
	proxy := &proxyEndpoint{
		proxyEndpointID: "preset-proxy",
		displayName:     "Preset Proxy",
		host:            "preset-proxy.local",
		addressCidr:     "192.168.0.126/32",
		port:            10809,
		protocol:        egressv1.ProxyProtocol_PROXY_PROTOCOL_HTTP_CONNECT,
		resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_NONE,
	}
	destinations := make([]*externalDestination, 0, gatewayAPIMaxHostnames+1)
	for i := 0; i < gatewayAPIMaxHostnames+1; i++ {
		destinations = append(destinations, &externalDestination{
			destinationID:   fmt.Sprintf("catalog.%02d", i),
			displayName:     fmt.Sprintf("Catalog %02d", i),
			host:            fmt.Sprintf("catalog-%02d.example.com", i),
			port:            443,
			protocol:        egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
			resolution:      egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
			proxyEndpointID: proxy.proxyEndpointID,
			proxyEndpoint:   proxy,
		})
	}
	objects := desiredObjects(egressRuntime{
		namespace:      "code-code-net",
		forwarderImage: "registry.local/code-code/platform-egress-forwarder:test",
	}, desiredState{
		destinations:   destinations,
		proxyEndpoints: []*proxyEndpoint{proxy},
	})

	firstRoute := objectByName(t, objects, "TLSRoute", proxyEndpointTLSRouteName("preset-proxy-01"))
	firstHostnames, ok, err := unstructured.NestedStringSlice(firstRoute.Object, "spec", "hostnames")
	if err != nil || !ok {
		t.Fatalf("first proxy tls hostnames not found: ok=%v err=%v", ok, err)
	}
	if got, want := len(firstHostnames), gatewayAPIMaxHostnames; got != want {
		t.Fatalf("first proxy tls hostnames = %d, want %d", got, want)
	}
	secondRoute := objectByName(t, objects, "TLSRoute", proxyEndpointTLSRouteName("preset-proxy-02"))
	secondHostnames, ok, err := unstructured.NestedStringSlice(secondRoute.Object, "spec", "hostnames")
	if err != nil || !ok {
		t.Fatalf("second proxy tls hostnames not found: ok=%v err=%v", ok, err)
	}
	if got, want := len(secondHostnames), 1; got != want {
		t.Fatalf("second proxy tls hostnames = %d, want %d", got, want)
	}
	if objectExists(objects, "TLSRoute", proxyEndpointTLSRouteName("preset-proxy")) {
		t.Fatal("unsplit proxy TLSRoute generated when hostnames exceed Gateway API limit")
	}
	if got := countObjects(objects, "Deployment", forwarderName("preset-proxy")); got != 1 {
		t.Fatalf("forwarder deployments = %d, want 1", got)
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
		httpInspectionRules: []*httpInspectionRule{{
			resourceID:         "support.openai-chat",
			inspectionRuleID:   "openai-chat",
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

func objectExists(objects []ctrlclient.Object, kind string, name string) bool {
	for _, obj := range objects {
		if obj.GetObjectKind().GroupVersionKind().Kind == kind && obj.GetName() == name {
			return true
		}
	}
	return false
}

func countObjects(objects []ctrlclient.Object, kind string, name string) int {
	count := 0
	for _, obj := range objects {
		if obj.GetObjectKind().GroupVersionKind().Kind == kind && obj.GetName() == name {
			count++
		}
	}
	return count
}

func nestedStringLabels(t *testing.T, object map[string]any, fields ...string) map[string]string {
	t.Helper()
	raw, ok, err := unstructured.NestedFieldNoCopy(object, fields...)
	if err != nil || !ok {
		t.Fatalf("labels not found at %v: ok=%v err=%v", fields, ok, err)
	}
	switch labels := raw.(type) {
	case map[string]string:
		return labels
	case map[string]any:
		out := make(map[string]string, len(labels))
		for key, value := range labels {
			text, ok := value.(string)
			if !ok {
				t.Fatalf("label %q has type %T, want string", key, value)
			}
			out[key] = text
		}
		return out
	default:
		t.Fatalf("labels at %v have type %T, want map", fields, raw)
		return nil
	}
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

func authPolicyWithServiceAccount(t *testing.T, policies []*unstructured.Unstructured, serviceAccount string) *unstructured.Unstructured {
	t.Helper()
	for _, policy := range policies {
		accounts := authorizationPolicyServiceAccounts(t, policy)
		for _, account := range accounts {
			if account == serviceAccount {
				return policy
			}
		}
	}
	t.Fatalf("no AuthorizationPolicy for service account %q found", serviceAccount)
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

func authorizationPolicyTargetNames(t *testing.T, policy *unstructured.Unstructured) []string {
	t.Helper()
	targetRefs, ok, err := unstructured.NestedSlice(policy.Object, "spec", "targetRefs")
	if err != nil || !ok {
		t.Fatalf("targetRefs not found: ok=%v err=%v", ok, err)
	}
	out := make([]string, 0, len(targetRefs))
	for _, ref := range targetRefs {
		refMap, ok := ref.(map[string]any)
		if !ok {
			t.Fatalf("targetRef has type %T, want map", ref)
		}
		name, ok := refMap["name"].(string)
		if !ok {
			t.Fatalf("targetRef name = %#v, want string", refMap["name"])
		}
		out = append(out, name)
	}
	return out
}

func serviceEntryHosts(t *testing.T, serviceEntry *unstructured.Unstructured) []string {
	t.Helper()
	hosts, ok, err := unstructured.NestedStringSlice(serviceEntry.Object, "spec", "hosts")
	if err != nil || !ok {
		t.Fatalf("ServiceEntry hosts not found: ok=%v err=%v", ok, err)
	}
	return hosts
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
