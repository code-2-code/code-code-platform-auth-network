package runtimeobservability

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
	"google.golang.org/protobuf/encoding/protojson"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
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

func (r *Reconciler) saveTelemetryProfileSet(ctx context.Context, capability *observabilityv1.ObservabilityCapability) error {
	raw, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(capability)
	if err != nil {
		return err
	}
	next := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.profileStoreName,
			Namespace: r.observabilityNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       r.profileStoreName,
				"app.kubernetes.io/component":  "observability",
				"app.kubernetes.io/managed-by": "platform-egress-service",
			},
		},
		Data: map[string]string{r.profileStoreKey: string(raw)},
	}
	current := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: next.Namespace, Name: next.Name}
	if err := r.client.Get(ctx, key, current); err != nil {
		if apierrors.IsNotFound(err) {
			return r.client.Create(ctx, next)
		}
		return err
	}
	if current.Data != nil && current.Data[r.profileStoreKey] == string(raw) {
		return nil
	}
	next = current.DeepCopy()
	if next.Labels == nil {
		next.Labels = map[string]string{}
	}
	next.Labels["app.kubernetes.io/managed-by"] = "platform-egress-service"
	if next.Data == nil {
		next.Data = map[string]string{}
	}
	next.Data[r.profileStoreKey] = string(raw)
	return r.client.Update(ctx, next)
}

func (r *Reconciler) loadTelemetryProfileSet(ctx context.Context) (*observabilityv1.ObservabilityCapability, error) {
	configMap := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: r.observabilityNamespace, Name: r.profileStoreName}
	if err := r.client.Get(ctx, key, configMap); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	raw := strings.TrimSpace(configMap.Data[r.profileStoreKey])
	if raw == "" {
		return nil, nil
	}
	capability := &observabilityv1.ObservabilityCapability{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal([]byte(raw), capability); err != nil {
		return nil, fmt.Errorf("platformk8s/egressservice/runtimeobservability: parse stored telemetry profiles: %w", err)
	}
	if err := observabilityv1.ValidateCapability(capability); err != nil {
		return nil, err
	}
	return capability, nil
}

func (r *Reconciler) applyCollectorConfig(ctx context.Context, rendered string) (bool, error) {
	next := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.collectorConfigMapName,
			Namespace: r.observabilityNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       r.collectorConfigMapName,
				"app.kubernetes.io/component":  "observability",
				"app.kubernetes.io/managed-by": "platform-egress-service",
			},
		},
		Data: map[string]string{r.collectorConfigKey: rendered},
	}
	current := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: next.Namespace, Name: next.Name}
	if err := r.client.Get(ctx, key, current); err != nil {
		if apierrors.IsNotFound(err) {
			return true, r.client.Create(ctx, next)
		}
		return false, err
	}
	if current.Data != nil && current.Data[r.collectorConfigKey] == rendered {
		return false, nil
	}
	next = current.DeepCopy()
	if next.Labels == nil {
		next.Labels = map[string]string{}
	}
	next.Labels["app.kubernetes.io/managed-by"] = "platform-egress-service"
	if next.Data == nil {
		next.Data = map[string]string{}
	}
	next.Data[r.collectorConfigKey] = rendered
	return true, r.client.Update(ctx, next)
}

func (r *Reconciler) applyTelemetry(ctx context.Context) error {
	targetGateways, err := r.l7TargetGatewayNames(ctx)
	if err != nil {
		return err
	}
	if len(targetGateways) == 0 {
		return r.deleteTelemetry(ctx)
	}
	next := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "telemetry.istio.io/v1",
		"kind":       "Telemetry",
		"metadata": map[string]any{
			"name":      r.telemetryName,
			"namespace": r.networkNamespace,
			"labels": map[string]any{
				"app.kubernetes.io/managed-by": "platform-egress-service",
			},
		},
		"spec": map[string]any{
			"targetRefs": telemetryTargetRefs(targetGateways),
			"accessLogging": []any{map[string]any{
				"providers": []any{map[string]any{"name": r.providerName}},
			}},
		},
	}}
	next.SetGroupVersionKind(telemetryGVK)
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(next.GroupVersionKind())
	key := types.NamespacedName{Namespace: r.networkNamespace, Name: r.telemetryName}
	if err := r.client.Get(ctx, key, current); err != nil {
		if apierrors.IsNotFound(err) {
			return r.client.Create(ctx, next)
		}
		return err
	}
	next.SetResourceVersion(current.GetResourceVersion())
	return r.client.Update(ctx, next)
}

func (r *Reconciler) l7TargetGatewayNames(ctx context.Context) ([]string, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(gatewayListGVK)
	if err := r.client.List(ctx, list, client.InNamespace(r.networkNamespace), client.MatchingLabels(l7GatewayLabels)); err != nil {
		return nil, fmt.Errorf("platformk8s/egressservice/runtimeobservability: list L7 egress gateways: %w", err)
	}
	names := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		if name := strings.TrimSpace(item.GetName()); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (r *Reconciler) deleteTelemetry(ctx context.Context) error {
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(telemetryGVK)
	key := types.NamespacedName{Namespace: r.networkNamespace, Name: r.telemetryName}
	if err := r.client.Get(ctx, key, current); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return r.client.Delete(ctx, current)
}

func telemetryTargetRefs(gatewayNames []string) []any {
	refs := make([]any, 0, len(gatewayNames))
	for _, name := range gatewayNames {
		refs = append(refs, map[string]any{
			"group": "gateway.networking.k8s.io",
			"kind":  "Gateway",
			"name":  name,
		})
	}
	return refs
}

func (r *Reconciler) applyIstioProvider(ctx context.Context, profiles []*observabilityv1.ObservabilityProfile) error {
	configMap := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: r.istioNamespace, Name: "istio"}
	if err := r.client.Get(ctx, key, configMap); err != nil {
		return err
	}
	data := configMap.Data
	if data == nil {
		data = map[string]string{}
	}
	mesh := map[string]any{}
	if raw := strings.TrimSpace(data["mesh"]); raw != "" {
		if err := yaml.Unmarshal([]byte(raw), &mesh); err != nil {
			return fmt.Errorf("platformk8s/egressservice/runtimeobservability: parse istio mesh config: %w", err)
		}
	}
	mesh["extensionProviders"] = upsertExtensionProvider(mesh["extensionProviders"], r.providerName, r.observabilityNamespace, profiles)
	rendered, err := yaml.Marshal(mesh)
	if err != nil {
		return err
	}
	next := configMap.DeepCopy()
	if next.Data == nil {
		next.Data = map[string]string{}
	}
	next.Data["mesh"] = string(rendered)
	return r.client.Update(ctx, next)
}

func (r *Reconciler) restartCollector(ctx context.Context, rendered string) error {
	deployment := &appsv1.Deployment{}
	key := types.NamespacedName{Namespace: r.observabilityNamespace, Name: r.collectorDeploymentName}
	if err := r.client.Get(ctx, key, deployment); err != nil {
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			return nil
		}
		return err
	}
	hash := collectorConfigHash(rendered)
	if deployment.Spec.Template.GetAnnotations()[collectorConfigHashAnnotation] == hash {
		return nil
	}
	next := deployment.DeepCopy()
	annotations := next.Spec.Template.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[collectorConfigHashAnnotation] = hash
	next.Spec.Template.SetAnnotations(annotations)
	return r.client.Update(ctx, next)
}

func collectorConfigHash(rendered string) string {
	sum := sha256.Sum256([]byte(rendered))
	return fmt.Sprintf("%x", sum[:])
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
