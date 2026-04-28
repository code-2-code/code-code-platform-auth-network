package telemetry

import (
	"regexp"
	"strings"
)

var semanticMetricNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// StorageMetricName normalizes a semantic metric name to a Prometheus storage name.
func StorageMetricName(metricName string) string {
	normalized := strings.TrimSpace(metricName)
	if normalized == "" {
		return ""
	}
	if strings.Contains(normalized, ".") {
		return strings.ReplaceAll(normalized, ".", "_")
	}
	return normalized
}

// IsSemanticMetricName reports whether a metric name follows dot-separated OTel style.
func IsSemanticMetricName(metricName string) bool {
	return semanticMetricNamePattern.MatchString(strings.TrimSpace(metricName))
}
