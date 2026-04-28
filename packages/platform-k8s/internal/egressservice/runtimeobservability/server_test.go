package runtimeobservability

import (
	"context"
	"strings"
	"testing"
	"time"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
	"google.golang.org/protobuf/encoding/protojson"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReconcileTelemetryTargetsCreatesTelemetryForStoredProfiles(t *testing.T) {
	client := fakeClient(t,
		runtimeTelemetryConfigMap("{}\n"),
		telemetryProfileStoreConfigMap(t),
		istioConfigMap(),
		l7Gateway("code-code-egress-gw-openai"),
	)
	server := testReconciler(t, client)

	if err := server.Reconcile(context.Background()); err != nil {
		t.Fatalf("ReconcileTelemetryTargets() error = %v", err)
	}

	telemetry := &unstructured.Unstructured{}
	telemetry.SetGroupVersionKind(telemetryGVK)
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: DefaultNetworkNamespace, Name: DefaultTelemetryName}, telemetry); err != nil {
		t.Fatalf("get telemetry: %v", err)
	}
	targetRefs, ok, err := unstructured.NestedSlice(telemetry.Object, "spec", "targetRefs")
	if err != nil || !ok || len(targetRefs) != 1 {
		t.Fatalf("targetRefs ok=%v len=%d err=%v", ok, len(targetRefs), err)
	}
	targetRef := targetRefs[0].(map[string]any)
	if got, want := targetRef["name"], "code-code-egress-gw-openai"; got != want {
		t.Fatalf("targetRef name = %v, want %v", got, want)
	}

	runtimeConfig := &corev1.ConfigMap{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: DefaultObservabilityNamespace, Name: DefaultCollectorConfigMapName}, runtimeConfig); err != nil {
		t.Fatalf("get runtime config: %v", err)
	}
	if got := runtimeConfig.Data[DefaultCollectorConfigKey]; !strings.Contains(got, runtimeHeaderConnectorName) {
		t.Fatalf("runtime config missing %q:\n%s", runtimeHeaderConnectorName, got)
	}
}

func TestReconcileTelemetryTargetsRestartsCollectorWhenRuntimeConfigAlreadyMatches(t *testing.T) {
	rendered, err := renderCollectorConfig([]*observabilityv1.ObservabilityProfile{testPassiveHTTPProfile()}, collectorConfigOptions{})
	if err != nil {
		t.Fatalf("renderCollectorConfig() error = %v", err)
	}
	client := fakeClient(t,
		runtimeTelemetryConfigMap(rendered),
		telemetryProfileStoreConfigMap(t),
		istioConfigMap(),
		l7Gateway("code-code-egress-gw-openai"),
		otelCollectorDeployment("stale"),
	)
	server := testReconciler(t, client)

	if err := server.Reconcile(context.Background()); err != nil {
		t.Fatalf("ReconcileTelemetryTargets() error = %v", err)
	}

	deployment := &appsv1.Deployment{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: DefaultObservabilityNamespace, Name: DefaultCollectorDeployment}, deployment); err != nil {
		t.Fatalf("get collector deployment: %v", err)
	}
	if got, want := deployment.Spec.Template.GetAnnotations()[collectorConfigHashAnnotation], collectorConfigHash(rendered); got != want {
		t.Fatalf("collector config hash annotation = %q, want %q", got, want)
	}
}

func TestReconcileTelemetryTargetsDeletesTelemetryWithoutL7Gateways(t *testing.T) {
	client := fakeClient(t,
		runtimeTelemetryConfigMap("{}\n"),
		telemetryProfileStoreConfigMap(t),
		istioConfigMap(),
		telemetryObject("code-code-egress-gw-openai"),
	)
	server := testReconciler(t, client)

	if err := server.Reconcile(context.Background()); err != nil {
		t.Fatalf("ReconcileTelemetryTargets() error = %v", err)
	}

	telemetry := &unstructured.Unstructured{}
	telemetry.SetGroupVersionKind(telemetryGVK)
	err := client.Get(context.Background(), types.NamespacedName{Namespace: DefaultNetworkNamespace, Name: DefaultTelemetryName}, telemetry)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get telemetry error = %v, want not found", err)
	}
}

func TestReconcileTelemetryTargetsDeletesTelemetryWithoutStoredProfiles(t *testing.T) {
	client := fakeClient(t,
		runtimeTelemetryConfigMap("service:\n  pipelines: {}\n"),
		istioConfigMap(),
		l7Gateway("code-code-egress-gw-openai"),
		telemetryObject("code-code-egress-gw-openai"),
	)
	server := testReconciler(t, client)

	if err := server.Reconcile(context.Background()); err != nil {
		t.Fatalf("ReconcileTelemetryTargets() error = %v", err)
	}

	telemetry := &unstructured.Unstructured{}
	telemetry.SetGroupVersionKind(telemetryGVK)
	err := client.Get(context.Background(), types.NamespacedName{Namespace: DefaultNetworkNamespace, Name: DefaultTelemetryName}, telemetry)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get telemetry error = %v, want not found", err)
	}
}

func fakeClient(t *testing.T, objects ...runtime.Object) ctrlclient.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
}

func testReconciler(t *testing.T, client ctrlclient.Client) *Reconciler {
	t.Helper()
	server, err := NewReconciler(Config{
		Client:                client,
		TelemetrySyncInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	return server
}

func runtimeTelemetryConfigMap(value string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DefaultCollectorConfigMapName,
			Namespace: DefaultObservabilityNamespace,
		},
		Data: map[string]string{
			DefaultCollectorConfigKey: value,
		},
	}
}

func telemetryProfileStoreConfigMap(t *testing.T) *corev1.ConfigMap {
	t.Helper()
	raw, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(&observabilityv1.ObservabilityCapability{
		Profiles: []*observabilityv1.ObservabilityProfile{testPassiveHTTPProfile()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DefaultProfileStoreName,
			Namespace: DefaultObservabilityNamespace,
		},
		Data: map[string]string{
			DefaultProfileStoreKey: string(raw),
		},
	}
}

func istioConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "istio",
			Namespace: DefaultIstioNamespace,
		},
		Data: map[string]string{"mesh": "{}\n"},
	}
}

func l7Gateway(name string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{}}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "Gateway"})
	obj.SetNamespace(DefaultNetworkNamespace)
	obj.SetName(name)
	obj.SetLabels(l7GatewayLabels)
	return obj
}

func telemetryObject(gatewayName string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"targetRefs": telemetryTargetRefs([]string{gatewayName}),
			"accessLogging": []any{map[string]any{
				"providers": []any{map[string]any{"name": DefaultProviderName}},
			}},
		},
	}}
	obj.SetGroupVersionKind(telemetryGVK)
	obj.SetNamespace(DefaultNetworkNamespace)
	obj.SetName(DefaultTelemetryName)
	return obj
}

func otelCollectorDeployment(hash string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DefaultCollectorDeployment,
			Namespace: DefaultObservabilityNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						collectorConfigHashAnnotation: hash,
					},
				},
			},
		},
	}
}
