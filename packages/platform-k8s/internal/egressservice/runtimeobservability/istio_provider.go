package runtimeobservability

import (
	"sort"
	"strings"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
)

func upsertExtensionProvider(current any, providerName string, observabilityNamespace string, profiles []*observabilityv1.ObservabilityProfile) []any {
	providers, _ := current.([]any)
	nextProvider := otelALSProvider(providerName, observabilityNamespace, profiles)
	out := make([]any, 0, len(providers)+1)
	replaced := false
	for _, item := range providers {
		asMap, ok := item.(map[string]any)
		if !ok {
			out = append(out, item)
			continue
		}
		if strings.TrimSpace(stringValue(asMap["name"])) == providerName {
			out = append(out, nextProvider)
			replaced = true
			continue
		}
		out = append(out, item)
	}
	if !replaced {
		out = append(out, nextProvider)
	}
	return out
}

func otelALSProvider(providerName string, observabilityNamespace string, profiles []*observabilityv1.ObservabilityProfile) map[string]any {
	requestHeaders, responseHeaders := telemetryHeaderNames(profiles)
	labels := map[string]any{
		"authority":             "%REQ(:AUTHORITY)%",
		"method":                "%REQ(:METHOD)%",
		"path":                  "%REQ(:PATH)%",
		"protocol":              "%PROTOCOL%",
		"response_code":         "%RESPONSE_CODE%",
		"response_code_details": "%RESPONSE_CODE_DETAILS%",
		"route_name":            "%ROUTE_NAME%",
		"upstream_cluster":      "%UPSTREAM_CLUSTER_RAW%",
		"provider_id":           "%REQ(X-CODE-CODE-PROVIDER-ID)%",
		"model_id":              "%REQ(X-CODE-CODE-MODEL-ID)%",
	}
	for _, header := range requestHeaders {
		labels["request_header_"+sanitizeHeaderAttributeName(header)] = "%REQ(" + strings.ToUpper(header) + ")%"
	}
	for _, header := range responseHeaders {
		labels["response_header_"+sanitizeHeaderAttributeName(header)] = "%RESP(" + strings.ToUpper(header) + ")%"
	}
	return map[string]any{
		"name": providerName,
		"envoyOtelAls": map[string]any{
			"service": "otel-collector." + observabilityNamespace + ".svc.cluster.local",
			"port":    4317,
			"logName": DefaultALSLogName,
			"logFormat": map[string]any{
				"labels": labels,
			},
		},
	}
}

func telemetryHeaderNames(profiles []*observabilityv1.ObservabilityProfile) ([]string, []string) {
	request := map[string]struct{}{}
	response := map[string]struct{}{}
	for _, profile := range profiles {
		for _, transform := range profile.GetPassiveHttp().GetTransforms() {
			header := strings.ToLower(strings.TrimSpace(transform.GetHeaderName()))
			if header == "" {
				continue
			}
			switch transform.GetSource() {
			case observabilityv1.HttpHeaderSource_HTTP_HEADER_SOURCE_REQUEST:
				request[header] = struct{}{}
			case observabilityv1.HttpHeaderSource_HTTP_HEADER_SOURCE_RESPONSE:
				response[header] = struct{}{}
			}
		}
	}
	return sortedKeys(request), sortedKeys(response)
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}
