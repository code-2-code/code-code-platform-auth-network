package egresspolicies

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func serviceEntryObject(runtime egressRuntime, group *serviceEntryGroup) ctrlclient.Object {
	spec := map[string]any{
		"hosts":      serviceEntryGroupHosts(group),
		"location":   "MESH_EXTERNAL",
		"ports":      serviceEntryGroupPorts(group),
		"resolution": serviceEntryGroupResolution(group),
	}
	if addressCidr := groupAddressCidr(group); addressCidr != "" {
		spec["addresses"] = []any{addressCidr}
	}
	labels := serviceEntryGroupLabels(egressRoleDestination, group)
	labels["istio.io/use-waypoint"] = egressWaypointName
	labels["istio.io/use-waypoint-namespace"] = runtime.namespace
	return newObject(
		serviceEntryGVK,
		runtime.namespace,
		serviceEntryName(group.groupID),
		labels,
		serviceEntryGroupAnnotations(group),
		spec,
	)
}

func proxyEndpointServiceEntryObject(runtime egressRuntime, endpoint *proxyEndpoint) ctrlclient.Object {
	spec := map[string]any{
		"hosts":    []any{endpoint.host},
		"location": "MESH_EXTERNAL",
		"ports": []any{map[string]any{
			"number":   int64(endpoint.port),
			"name":     "tcp-" + fmt.Sprint(endpoint.port),
			"protocol": "TCP",
		}},
		"resolution": resolutionString(endpoint.resolution),
	}
	if endpoint.addressCidr != "" {
		spec["addresses"] = []any{endpoint.addressCidr}
	}
	labels := proxyEndpointLabels(egressRoleProxyEndpoint, endpoint)
	labels["istio.io/use-waypoint"] = egressWaypointName
	labels["istio.io/use-waypoint-namespace"] = runtime.namespace
	return newObject(
		serviceEntryGVK,
		runtime.namespace,
		proxyEndpointServiceEntryName(endpoint.proxyEndpointID),
		labels,
		proxyEndpointAnnotations(endpoint),
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

func directHTTPRouteObject(runtime egressRuntime, route *httpInspectionRule) ctrlclient.Object {
	spec := map[string]any{
		"parentRefs": []any{map[string]any{
			"group": "networking.istio.io",
			"kind":  "ServiceEntry",
			"name":  serviceEntryNameForDestination(route.destination),
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

func forwardHTTPRouteObject(runtime egressRuntime, route *httpInspectionRule) ctrlclient.Object {
	rule := map[string]any{
		"backendRefs": []any{forwardHTTPRouteBackendRef(route)},
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

func forwardHTTPRouteBackendRef(route *httpInspectionRule) any {
	return map[string]any{
		"group": "networking.istio.io",
		"kind":  "Hostname",
		"name":  route.destination.host,
		"port":  int64(route.destination.port),
	}
}

func proxyEndpointTLSRouteObject(runtime egressRuntime, group *proxyEndpointDestinationGroup) ctrlclient.Object {
	spec := map[string]any{
		"parentRefs": proxyEndpointTLSRouteParentRefs(group.destinations),
		"hostnames":  proxyEndpointTLSRouteHostnames(group.destinations),
		"rules": []any{map[string]any{
			"backendRefs": []any{map[string]any{
				"name": forwarderName(group.proxyEndpoint.proxyEndpointID),
				"port": int64(egressForwarderPort),
			}},
		}},
	}
	return newObject(
		tlsRouteGVK,
		runtime.namespace,
		proxyEndpointTLSRouteName(group.routeID),
		forwarderLabels(egressRoleDirectTLSRoute, group),
		proxyForwarderAnnotations(group),
		spec,
	)
}

func proxyEndpointTLSRouteParentRefs(destinations []*externalDestination) []any {
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

func proxyEndpointTLSRouteHostnames(destinations []*externalDestination) []any {
	hostnames := make([]any, 0, len(destinations))
	for _, destination := range destinations {
		hostnames = append(hostnames, destination.host)
	}
	return hostnames
}

func forwarderServiceAccountObject(runtime egressRuntime) ctrlclient.Object {
	return newObject(
		serviceAccountGVK,
		runtime.namespace,
		egressForwarderSAName,
		mergeStringMaps(gatewayLabels(), map[string]string{labelEgressRole: egressRoleForwarderSA}),
		map[string]string{annotationDisplayName: "Egress forwarder"},
		nil,
	)
}

func forwarderConfigObject(runtime egressRuntime, group *proxyEndpointDestinationGroup) ctrlclient.Object {
	return newConfigMapObject(
		runtime.namespace,
		forwarderConfigName(group.proxyEndpoint.proxyEndpointID),
		forwarderLabels(egressRoleForwarderConfig, group),
		proxyForwarderAnnotations(group),
		map[string]string{
			"config.yaml": gostForwarderConfig(group),
		},
	)
}

func forwarderDeploymentObject(runtime egressRuntime, group *proxyEndpointDestinationGroup) ctrlclient.Object {
	name := forwarderName(group.proxyEndpoint.proxyEndpointID)
	labels := forwarderLabels(egressRoleForwarder, group)
	selectorLabels := forwarderPodSelectorLabels(name, group)
	templateLabels := mergeStringMaps(labels, selectorLabels)
	templateLabels["istio.io/dataplane-mode"] = "none"
	spec := map[string]any{
		"replicas": int64(1),
		"selector": map[string]any{
			"matchLabels": selectorLabels,
		},
		"template": map[string]any{
			"metadata": map[string]any{
				"labels": templateLabels,
			},
			"spec": map[string]any{
				"serviceAccountName":            egressForwarderSAName,
				"automountServiceAccountToken":  false,
				"terminationGracePeriodSeconds": int64(10),
				"securityContext": map[string]any{
					"runAsNonRoot": true,
					"runAsUser":    int64(65532),
					"runAsGroup":   int64(65532),
					"seccompProfile": map[string]any{
						"type": "RuntimeDefault",
					},
				},
				"containers": []any{map[string]any{
					"name":  "gost",
					"image": runtime.forwarderImage,
					"args":  []any{"-C", "/etc/gost/config.yaml"},
					"ports": []any{map[string]any{
						"name":          "tls-tunnel",
						"containerPort": int64(egressForwarderPort),
					}},
					"securityContext": map[string]any{
						"allowPrivilegeEscalation": false,
						"readOnlyRootFilesystem":   true,
						"capabilities": map[string]any{
							"drop": []any{"ALL"},
						},
					},
					"resources": map[string]any{
						"requests": map[string]any{"cpu": "10m", "memory": "32Mi"},
						"limits":   map[string]any{"cpu": "100m", "memory": "128Mi"},
					},
					"volumeMounts": []any{map[string]any{
						"name":      "config",
						"mountPath": "/etc/gost",
						"readOnly":  true,
					}},
				}},
				"volumes": []any{map[string]any{
					"name": "config",
					"configMap": map[string]any{
						"name": forwarderConfigName(group.proxyEndpoint.proxyEndpointID),
					},
				}},
			},
		},
	}
	return newObject(deploymentGVK, runtime.namespace, name, labels, proxyForwarderAnnotations(group), spec)
}

func forwarderServiceObject(runtime egressRuntime, group *proxyEndpointDestinationGroup) ctrlclient.Object {
	name := forwarderName(group.proxyEndpoint.proxyEndpointID)
	spec := map[string]any{
		"type":     "ClusterIP",
		"selector": forwarderPodSelectorLabels(name, group),
		"ports": []any{map[string]any{
			"name":       "tls-tunnel",
			"port":       int64(egressForwarderPort),
			"targetPort": "tls-tunnel",
			"protocol":   "TCP",
		}},
	}
	return newObject(serviceGVK, runtime.namespace, name, forwarderLabels(egressRoleForwarder, group), proxyForwarderAnnotations(group), spec)
}

func forwarderNetworkPolicyObject(runtime egressRuntime, group *proxyEndpointDestinationGroup) ctrlclient.Object {
	spec := map[string]any{
		"podSelector": map[string]any{
			"matchLabels": forwarderPodSelectorLabels(forwarderName(group.proxyEndpoint.proxyEndpointID), group),
		},
		"policyTypes": []any{"Ingress", "Egress"},
		"ingress": []any{map[string]any{
			"from": []any{map[string]any{
				"podSelector": map[string]any{
					"matchLabels": map[string]any{
						"gateway.networking.k8s.io/gateway-name": egressWaypointName,
					},
				},
			}},
			"ports": []any{map[string]any{
				"protocol": "TCP",
				"port":     int64(egressForwarderPort),
			}},
		}},
		"egress": []any{map[string]any{
			"to": []any{map[string]any{
				"ipBlock": map[string]any{
					"cidr": group.proxyEndpoint.addressCidr,
				},
			}},
			"ports": []any{map[string]any{
				"protocol": "TCP",
				"port":     int64(group.proxyEndpoint.port),
			}},
		}},
	}
	return newObject(
		networkPolicyGVK,
		runtime.namespace,
		forwarderNetworkPolicyName(group.proxyEndpoint.proxyEndpointID),
		forwarderLabels(egressRoleForwarderNetpol, group),
		proxyForwarderAnnotations(group),
		spec,
	)
}

func forwarderPodSelectorLabels(name string, group *proxyEndpointDestinationGroup) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      name,
		"app.kubernetes.io/component": "egress-forwarder",
		labelEgressRoute:              destinationLabelValue(group.proxyEndpoint.proxyEndpointID),
	}
}

func gostForwarderConfig(group *proxyEndpointDestinationGroup) string {
	proxyAddr := proxyEndpointAddress(group.proxyEndpoint) + ":" + fmt.Sprint(group.proxyEndpoint.port)
	var b strings.Builder
	b.WriteString("services:\n")
	b.WriteString("- name: egress-forwarder\n")
	b.WriteString("  addr: \":")
	b.WriteString(strconv.Itoa(egressForwarderPort))
	b.WriteString("\"\n")
	b.WriteString("  handler:\n")
	b.WriteString("    type: sni\n")
	b.WriteString("    chain: proxy-chain\n")
	b.WriteString("  listener:\n")
	b.WriteString("    type: tcp\n")
	b.WriteString("chains:\n")
	b.WriteString("- name: proxy-chain\n")
	b.WriteString("  hops:\n")
	b.WriteString("  - name: proxy-hop\n")
	b.WriteString("    nodes:\n")
	b.WriteString("    - name: proxy\n")
	b.WriteString("      addr: ")
	b.WriteString(strconv.Quote(proxyAddr))
	b.WriteString("\n")
	b.WriteString("      connector:\n")
	b.WriteString("        type: ")
	b.WriteString(strconv.Quote(gostConnectorType(group.proxyEndpoint.protocol)))
	b.WriteString("\n")
	b.WriteString("      dialer:\n")
	b.WriteString("        type: tcp\n")
	b.WriteString("log:\n")
	b.WriteString("  output: stderr\n")
	b.WriteString("  level: warn\n")
	b.WriteString("  format: json\n")
	return b.String()
}

func gostConnectorType(protocol egressv1.ProxyProtocol) string {
	switch protocol {
	case egressv1.ProxyProtocol_PROXY_PROTOCOL_SOCKS5:
		return "socks5"
	default:
		return "http"
	}
}

func proxyEndpointAddress(endpoint *proxyEndpoint) string {
	prefix, err := netip.ParsePrefix(endpoint.addressCidr)
	if err == nil {
		return prefix.Addr().String()
	}
	return endpoint.host
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
