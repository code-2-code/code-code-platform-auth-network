package runtimeobservability

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DefaultNetworkNamespace       = "code-code-net"
	DefaultObservabilityNamespace = "code-code-observability"
	DefaultIstioNamespace         = "istio-system"
	DefaultTelemetryName          = "code-code-egress-llm-access-logs"
	DefaultProviderName           = "code-code-egress-otel-logs"
	DefaultCollectorConfigMapName = "otel-collector-runtime-config"
	DefaultCollectorConfigKey     = "runtime-telemetry.yaml"
	DefaultProfileStoreName       = "otel-collector-runtime-profiles"
	DefaultProfileStoreKey        = "profiles.json"
	DefaultCollectorDeployment    = "otel-collector"
	DefaultLokiEndpoint           = "http://loki.code-code-observability.svc.cluster.local:3100/otlp"
	DefaultALSLogName             = "code-code-egress-http"
	DefaultTelemetrySyncInterval  = 30 * time.Second

	collectorConfigHashAnnotation = "code-code.internal/runtime-telemetry-config-sha256"
)

var (
	gatewayListGVK = schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1",
		Kind:    "GatewayList",
	}
	telemetryGVK    = schema.GroupVersionKind{Group: "telemetry.istio.io", Version: "v1", Kind: "Telemetry"}
	l7GatewayLabels = map[string]string{
		"app.kubernetes.io/name":                  "code-code-egress",
		"app.kubernetes.io/component":             "egress-policy",
		"app.kubernetes.io/managed-by":            "platform-egress-service",
		"egress.platform.code-code.internal/role": "l7-egress-gateway",
	}
)

type Config struct {
	Client                   client.Client
	NetworkNamespace         string
	ObservabilityNamespace   string
	IstioNamespace           string
	TelemetryName            string
	ProviderName             string
	CollectorConfigMapName   string
	CollectorConfigKey       string
	ProfileStoreName         string
	ProfileStoreKey          string
	CollectorDeploymentName  string
	LokiEndpoint             string
	EnableLLMHeaderLogExport bool
	TelemetrySyncInterval    time.Duration
	Logger                   *slog.Logger
}

type Reconciler struct {
	client                   client.Client
	networkNamespace         string
	observabilityNamespace   string
	istioNamespace           string
	telemetryName            string
	providerName             string
	collectorConfigMapName   string
	collectorConfigKey       string
	profileStoreName         string
	profileStoreKey          string
	collectorDeploymentName  string
	lokiEndpoint             string
	enableLLMHeaderLogExport bool
	telemetrySyncInterval    time.Duration
	logger                   *slog.Logger
}

type ApplyRuntimeTelemetryProfileSetCommand struct {
	ProfileSetID string
	Capability   *observabilityv1.ObservabilityCapability
}

type ApplyRuntimeTelemetryProfileSetResult struct {
	Applied      bool
	ProfileCount uint32
}

func NewReconciler(config Config) (*Reconciler, error) {
	if config.Client == nil {
		return nil, fmt.Errorf("platformk8s/egressservice/runtimeobservability: client is nil")
	}
	reconciler := &Reconciler{
		client:                   config.Client,
		networkNamespace:         firstNonEmpty(config.NetworkNamespace, DefaultNetworkNamespace),
		observabilityNamespace:   firstNonEmpty(config.ObservabilityNamespace, DefaultObservabilityNamespace),
		istioNamespace:           firstNonEmpty(config.IstioNamespace, DefaultIstioNamespace),
		telemetryName:            firstNonEmpty(config.TelemetryName, DefaultTelemetryName),
		providerName:             firstNonEmpty(config.ProviderName, DefaultProviderName),
		collectorConfigMapName:   firstNonEmpty(config.CollectorConfigMapName, DefaultCollectorConfigMapName),
		collectorConfigKey:       firstNonEmpty(config.CollectorConfigKey, DefaultCollectorConfigKey),
		profileStoreName:         firstNonEmpty(config.ProfileStoreName, DefaultProfileStoreName),
		profileStoreKey:          firstNonEmpty(config.ProfileStoreKey, DefaultProfileStoreKey),
		collectorDeploymentName:  firstNonEmpty(config.CollectorDeploymentName, DefaultCollectorDeployment),
		lokiEndpoint:             firstNonEmpty(config.LokiEndpoint, DefaultLokiEndpoint),
		enableLLMHeaderLogExport: config.EnableLLMHeaderLogExport,
		telemetrySyncInterval:    config.TelemetrySyncInterval,
		logger:                   config.Logger,
	}
	if reconciler.telemetrySyncInterval <= 0 {
		reconciler.telemetrySyncInterval = DefaultTelemetrySyncInterval
	}
	if reconciler.logger == nil {
		reconciler.logger = slog.Default()
	}
	return reconciler, nil
}

func (r *Reconciler) Run(ctx context.Context) {
	if r == nil {
		return
	}
	if err := r.Reconcile(ctx); err != nil && ctx.Err() == nil {
		r.logger.Warn("reconcile telemetry targets failed", "error", err)
	}
	ticker := time.NewTicker(r.telemetrySyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.Reconcile(ctx); err != nil && ctx.Err() == nil {
				r.logger.Warn("reconcile telemetry targets failed", "error", err)
			}
		}
	}
}

func (r *Reconciler) Reconcile(ctx context.Context) error {
	capability, err := r.loadTelemetryProfileSet(ctx)
	if err != nil {
		return err
	}
	if capability == nil {
		return r.disableRuntimeTelemetry(ctx)
	}
	profiles := passiveHTTPProfiles(capability)
	if len(profiles) == 0 {
		return r.disableRuntimeTelemetry(ctx)
	}
	return r.applyRuntimeTelemetry(ctx, profiles)
}

func (r *Reconciler) ApplyRuntimeTelemetryProfileSet(ctx context.Context, command ApplyRuntimeTelemetryProfileSetCommand) (*ApplyRuntimeTelemetryProfileSetResult, error) {
	if strings.TrimSpace(command.ProfileSetID) == "" {
		return nil, fmt.Errorf("platformk8s/egressservice/runtimeobservability: profile_set_id is empty")
	}
	capability := command.Capability
	if capability == nil {
		return nil, fmt.Errorf("platformk8s/egressservice/runtimeobservability: capability is nil")
	}
	if err := observabilityv1.ValidateCapability(capability); err != nil {
		return nil, err
	}
	if err := r.saveTelemetryProfileSet(ctx, capability); err != nil {
		return nil, err
	}
	profiles := passiveHTTPProfiles(capability)
	if len(profiles) == 0 {
		if err := r.disableRuntimeTelemetry(ctx); err != nil {
			return nil, err
		}
		return &ApplyRuntimeTelemetryProfileSetResult{}, nil
	}
	if err := r.applyRuntimeTelemetry(ctx, profiles); err != nil {
		return nil, err
	}
	return &ApplyRuntimeTelemetryProfileSetResult{
		Applied:      true,
		ProfileCount: uint32(len(profiles)),
	}, nil
}

func (r *Reconciler) applyRuntimeTelemetry(ctx context.Context, profiles []*observabilityv1.ObservabilityProfile) error {
	collectorConfig, err := renderCollectorConfig(profiles, collectorConfigOptions{
		LokiEndpoint:             r.lokiEndpoint,
		EnableLLMHeaderLogExport: r.enableLLMHeaderLogExport,
	})
	if err != nil {
		return err
	}
	if _, err := r.applyCollectorConfig(ctx, collectorConfig); err != nil {
		return err
	}
	if err := r.applyTelemetry(ctx); err != nil {
		return err
	}
	if err := r.applyIstioProvider(ctx, profiles); err != nil {
		return err
	}
	if err := r.restartCollector(ctx, collectorConfig); err != nil {
		r.logger.Warn("restart otel collector after telemetry config update failed", "error", err)
	}
	return nil
}

func (r *Reconciler) disableRuntimeTelemetry(ctx context.Context) error {
	rendered := "{}\n"
	if _, err := r.applyCollectorConfig(ctx, rendered); err != nil {
		return err
	}
	if err := r.deleteTelemetry(ctx); err != nil {
		return err
	}
	if err := r.restartCollector(ctx, rendered); err != nil {
		r.logger.Warn("restart otel collector after telemetry config update failed", "error", err)
	}
	return nil
}

func passiveHTTPProfiles(capability *observabilityv1.ObservabilityCapability) []*observabilityv1.ObservabilityProfile {
	out := make([]*observabilityv1.ObservabilityProfile, 0, len(capability.GetProfiles()))
	for _, profile := range capability.GetProfiles() {
		if profile != nil && profile.GetPassiveHttp() != nil {
			out = append(out, profile)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.TrimSpace(out[i].GetProfileId()) < strings.TrimSpace(out[j].GetProfileId())
	})
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
