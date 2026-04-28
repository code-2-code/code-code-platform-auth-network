package runtimeobservability

import (
	"fmt"
	"sort"
	"strings"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
	"code-code.internal/platform-k8s/internal/platform/telemetry"
	"sigs.k8s.io/yaml"
)

const runtimeHeaderConnectorName = "signal_to_metrics/code-code-llm-headers"

type collectorConfigOptions struct {
	LokiEndpoint             string
	EnableLLMHeaderLogExport bool
}

func renderCollectorConfig(profiles []*observabilityv1.ObservabilityProfile, options collectorConfigOptions) (string, error) {
	metrics := signalMetricConfigs(profiles)
	if len(metrics) == 0 {
		return "", fmt.Errorf("platformk8s/egressservice/runtimeobservability: passive http profiles contain no header transforms")
	}
	logExporters := []any{runtimeHeaderConnectorName}
	exporters := map[string]any{}
	if options.EnableLLMHeaderLogExport {
		endpoint := firstNonEmpty(options.LokiEndpoint, DefaultLokiEndpoint)
		exporters["otlp_http/loki"] = map[string]any{"endpoint": endpoint}
		logExporters = append(logExporters, "otlp_http/loki")
	}
	config := map[string]any{
		"connectors": map[string]any{
			runtimeHeaderConnectorName: map[string]any{
				"error_mode": "ignore",
				"logs":       metrics,
			},
		},
		"processors": map[string]any{
			"transform/code-code-llm-headers": map[string]any{
				"error_mode": "ignore",
				"log_statements": []any{map[string]any{
					"context": "log",
					"statements": []any{
						`set(log.attributes["host"], log.attributes["authority"]) where log.attributes["host"] == nil and log.attributes["authority"] != nil`,
					},
				}},
			},
		},
		"service": map[string]any{
			"pipelines": map[string]any{
				"logs/code-code-llm-headers": map[string]any{
					"receivers":  []any{"otlp"},
					"processors": []any{"transform/code-code-llm-headers", "batch"},
					"exporters":  logExporters,
				},
				"metrics/code-code-llm-headers": map[string]any{
					"receivers":  []any{runtimeHeaderConnectorName},
					"processors": []any{"batch"},
					"exporters":  []any{"otlp_http/prometheus"},
				},
			},
		},
	}
	if len(exporters) > 0 {
		config["exporters"] = exporters
	}
	rendered, err := yaml.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(rendered), nil
}

func signalMetricConfigs(profiles []*observabilityv1.ObservabilityProfile) []any {
	metricsByName := map[string]*observabilityv1.ObservabilityMetric{}
	items := make([]any, 0)
	seen := map[string]struct{}{}
	for _, profile := range profiles {
		if profile == nil || profile.GetPassiveHttp() == nil {
			continue
		}
		for _, metric := range profile.GetMetrics() {
			if metric == nil {
				continue
			}
			metricsByName[strings.TrimSpace(metric.GetName())] = metric
		}
		for _, transform := range profile.GetPassiveHttp().GetTransforms() {
			if transform == nil {
				continue
			}
			metric := metricsByName[strings.TrimSpace(transform.GetMetricName())]
			if metric == nil {
				continue
			}
			attributeName := telemetryAttributeName(transform)
			if attributeName == "" {
				continue
			}
			key := strings.Join([]string{
				transform.GetSource().String(),
				strings.TrimSpace(transform.GetHeaderName()),
				strings.TrimSpace(transform.GetMetricName()),
				fixedLabelKey(transform.GetLabels()),
			}, "\x00")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			items = append(items, signalMetricConfig(metric, transform, attributeName))
		}
	}
	return items
}

func signalMetricConfig(metric *observabilityv1.ObservabilityMetric, transform *observabilityv1.HttpHeaderTelemetryTransform, attributeName string) map[string]any {
	item := map[string]any{
		"name":        strings.TrimSpace(metric.GetName()),
		"description": strings.TrimSpace(metric.GetDescription()),
		"unit":        strings.TrimSpace(metric.GetUnit()),
		"conditions": []any{
			numericHeaderCondition(attributeName),
		},
		"attributes": signalMetricAttributes(metric, transform),
	}
	valueExpression := fmt.Sprintf(`Double(attributes["%s"])`, attributeName)
	if metric.GetKind() == observabilityv1.ObservabilityMetricKind_OBSERVABILITY_METRIC_KIND_COUNTER {
		item["sum"] = map[string]any{
			"value":       valueExpression,
			"aggregation": "cumulative",
		}
	} else {
		item["gauge"] = map[string]any{"value": valueExpression}
	}
	return item
}

func numericHeaderCondition(attributeName string) string {
	return fmt.Sprintf(`attributes["%s"] != nil and IsMatch(String(attributes["%s"]), "^[+-]?[0-9]+(\\.[0-9]+)?$")`, attributeName, attributeName)
}

func signalMetricAttributes(metric *observabilityv1.ObservabilityMetric, transform *observabilityv1.HttpHeaderTelemetryTransform) []any {
	fixed := map[string]string{}
	for _, label := range transform.GetLabels() {
		if label == nil {
			continue
		}
		name := telemetry.StorageMetricName(strings.TrimSpace(label.GetName()))
		value := strings.TrimSpace(label.GetValue())
		if name != "" && value != "" {
			fixed[name] = value
		}
	}
	attributes := make([]any, 0, len(metric.GetAttributes()))
	for _, attribute := range metric.GetAttributes() {
		if attribute == nil {
			continue
		}
		name := telemetry.StorageMetricName(strings.TrimSpace(attribute.GetName()))
		if name == "" {
			continue
		}
		item := map[string]any{"key": name}
		if value := fixed[name]; value != "" {
			item["default_value"] = value
		} else if attribute.GetRequirementLevel() != observabilityv1.ObservabilityAttributeRequirementLevel_OBSERVABILITY_ATTRIBUTE_REQUIREMENT_LEVEL_REQUIRED {
			item["optional"] = true
		}
		attributes = append(attributes, item)
	}
	return attributes
}

func telemetryAttributeName(transform *observabilityv1.HttpHeaderTelemetryTransform) string {
	headerName := sanitizeHeaderAttributeName(transform.GetHeaderName())
	if headerName == "" {
		return ""
	}
	switch transform.GetSource() {
	case observabilityv1.HttpHeaderSource_HTTP_HEADER_SOURCE_REQUEST:
		return "request_header_" + headerName
	case observabilityv1.HttpHeaderSource_HTTP_HEADER_SOURCE_RESPONSE:
		return "response_header_" + headerName
	default:
		return ""
	}
}

func sanitizeHeaderAttributeName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("-", "_", ".", "_")
	value = replacer.Replace(value)
	return telemetry.StorageMetricName(value)
}

func fixedLabelKey(labels []*observabilityv1.TelemetryMetricLabel) string {
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		if label == nil {
			continue
		}
		parts = append(parts, strings.TrimSpace(label.GetName())+"="+strings.TrimSpace(label.GetValue()))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
