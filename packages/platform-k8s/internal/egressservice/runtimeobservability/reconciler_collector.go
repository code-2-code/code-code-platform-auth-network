package runtimeobservability

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
)

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
