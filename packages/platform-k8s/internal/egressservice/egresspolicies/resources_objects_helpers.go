package egresspolicies

import (
	"fmt"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

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

func headerModifierFilters(route *httpInspectionRule) []any {
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

func newObject(gvk schema.GroupVersionKind, namespace string, name string, labels map[string]string, annotations map[string]string, spec map[string]any) *unstructured.Unstructured {
	object := map[string]any{}
	if spec != nil {
		object["spec"] = spec
	}
	obj := &unstructured.Unstructured{Object: object}
	obj.SetGroupVersionKind(gvk)
	obj.SetNamespace(namespace)
	obj.SetName(name)
	obj.SetLabels(labels)
	obj.SetAnnotations(annotations)
	return obj
}

func newConfigMapObject(namespace string, name string, labels map[string]string, annotations map[string]string, data map[string]string) ctrlclient.Object {
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

func stringSliceAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
