package runtimeobservability

import (
	"context"
	"fmt"
	"sort"
	"strings"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

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
