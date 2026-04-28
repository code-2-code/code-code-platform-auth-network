package runtimeobservability

import (
	"strings"
	"testing"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
)

func TestRenderCollectorConfigBuildsSignalToMetricsPipeline(t *testing.T) {
	profiles := []*observabilityv1.ObservabilityProfile{testPassiveHTTPProfile()}

	rendered, err := renderCollectorConfig(profiles, collectorConfigOptions{EnableLLMHeaderLogExport: true})
	if err != nil {
		t.Fatalf("renderCollectorConfig() error = %v", err)
	}
	for _, want := range []string{
		"signal_to_metrics/code-code-llm-headers",
		"gen_ai.provider.runtime.rate_limit.remaining",
		"response_header_x_ratelimit_remaining_requests",
		`IsMatch(String(attributes["response_header_x_ratelimit_remaining_requests"])`,
		"otlp_http/loki",
		"otlp_http/prometheus",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered config missing %q:\n%s", want, rendered)
		}
	}
}

func TestSignalMetricConfigsDeduplicatesSharedProtocolTransforms(t *testing.T) {
	first := testPassiveHTTPProfile()
	second := testPassiveHTTPProfile()
	second.ProfileId = "test.responses-runtime-http-telemetry"

	items := signalMetricConfigs([]*observabilityv1.ObservabilityProfile{first, second})
	if got, want := len(items), 1; got != want {
		t.Fatalf("len(signalMetricConfigs()) = %d, want %d", got, want)
	}
}

func TestOtelALSProviderIncludesOnlySelectedHeaders(t *testing.T) {
	provider := otelALSProvider(DefaultProviderName, DefaultObservabilityNamespace, []*observabilityv1.ObservabilityProfile{testPassiveHTTPProfile()})
	als := provider["envoyOtelAls"].(map[string]any)
	labels := als["logFormat"].(map[string]any)["labels"].(map[string]any)

	if _, ok := labels["response_header_x_ratelimit_remaining_requests"]; !ok {
		t.Fatalf("labels = %#v, want selected response header", labels)
	}
	if _, ok := labels["request_header_authorization"]; ok {
		t.Fatalf("labels = %#v, must not include authorization", labels)
	}
}

func testPassiveHTTPProfile() *observabilityv1.ObservabilityProfile {
	return &observabilityv1.ObservabilityProfile{
		ProfileId:   "test.runtime-http-telemetry",
		DisplayName: "Test Runtime HTTP Telemetry",
		Metrics: []*observabilityv1.ObservabilityMetric{{
			Name:        "gen_ai.provider.runtime.rate_limit.remaining",
			Description: "Remaining limit.",
			Unit:        "{count}",
			Kind:        observabilityv1.ObservabilityMetricKind_OBSERVABILITY_METRIC_KIND_GAUGE,
			Category:    observabilityv1.ObservabilityMetricCategory_OBSERVABILITY_METRIC_CATEGORY_RATE_LIMIT,
			Attributes: []*observabilityv1.ObservabilityMetricAttribute{{
				Name:             "resource",
				Description:      "Resource.",
				RequirementLevel: observabilityv1.ObservabilityAttributeRequirementLevel_OBSERVABILITY_ATTRIBUTE_REQUIREMENT_LEVEL_REQUIRED,
			}},
		}},
		Collection: &observabilityv1.ObservabilityProfile_PassiveHttp{
			PassiveHttp: &observabilityv1.PassiveHttpTelemetryCollection{
				CapturePoint: observabilityv1.TelemetryCapturePoint_TELEMETRY_CAPTURE_POINT_EGRESS,
				Redaction: &observabilityv1.HeaderRedactionPolicy{
					DropRawHeaders: true,
				},
				Transforms: []*observabilityv1.HttpHeaderTelemetryTransform{{
					Source:     observabilityv1.HttpHeaderSource_HTTP_HEADER_SOURCE_RESPONSE,
					HeaderName: "x-ratelimit-remaining-requests",
					MetricName: "gen_ai.provider.runtime.rate_limit.remaining",
					ValueType:  observabilityv1.HeaderValueType_HEADER_VALUE_TYPE_INT64,
					Labels: []*observabilityv1.TelemetryMetricLabel{{
						Name:  "resource",
						Value: "requests",
					}},
				}},
			},
		},
	}
}
