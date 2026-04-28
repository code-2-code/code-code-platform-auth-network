package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	egressservicev1 "code-code.internal/go-contract/platform/egress/v1"
	"code-code.internal/platform-k8s/internal/egressservice"
	"code-code.internal/platform-k8s/internal/egressservice/runtimeobservability"
	"code-code.internal/platform-k8s/internal/platform/telemetry"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	istionetworkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {
	addr := envOrDefault("PLATFORM_EGRESS_SERVICE_GRPC_ADDR", ":8081")
	namespace := envOrDefault("PLATFORM_EGRESS_SERVICE_NAMESPACE", "code-code")
	egressNamespace := envOrDefault("PLATFORM_EGRESS_SERVICE_EGRESS_NAMESPACE", "code-code-net")
	dynamicHeaderAuthzProviderName := envOrDefault("PLATFORM_EGRESS_SERVICE_DYNAMIC_HEADER_AUTHZ_PROVIDER_NAME", "")
	enableLLMHeaderLogs := boolEnv("PLATFORM_EGRESS_SERVICE_ENABLE_LLM_HEADER_LOGS")
	telemetrySyncInterval := durationEnvOrDefault("PLATFORM_EGRESS_SERVICE_TELEMETRY_SYNC_INTERVAL", runtimeobservability.DefaultTelemetrySyncInterval)

	telemetryShutdown, err := telemetry.Setup(context.Background(), envOrDefault("OTEL_SERVICE_NAME", "platform-egress-service"))
	must(err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = telemetryShutdown(ctx)
	}()

	scheme := runtime.NewScheme()
	must(appsv1.AddToScheme(scheme))
	must(corev1.AddToScheme(scheme))
	must(istionetworkingv1.AddToScheme(scheme))

	restConfig := ctrl.GetConfigOrDie()
	kubeClient, err := ctrlclient.New(restConfig, ctrlclient.Options{Scheme: scheme})
	must(err)

	server, err := egressservice.NewServer(egressservice.Config{
		Client:                         kubeClient,
		Reader:                         kubeClient,
		Namespace:                      namespace,
		EgressNamespace:                egressNamespace,
		DynamicHeaderAuthzProviderName: dynamicHeaderAuthzProviderName,
		RuntimeTelemetry: runtimeobservability.Config{
			Client:                   kubeClient,
			NetworkNamespace:         egressNamespace,
			ObservabilityNamespace:   envOrDefault("PLATFORM_EGRESS_SERVICE_OBSERVABILITY_NAMESPACE", runtimeobservability.DefaultObservabilityNamespace),
			IstioNamespace:           envOrDefault("PLATFORM_EGRESS_SERVICE_ISTIO_NAMESPACE", runtimeobservability.DefaultIstioNamespace),
			TelemetryName:            envOrDefault("PLATFORM_EGRESS_SERVICE_TELEMETRY_NAME", runtimeobservability.DefaultTelemetryName),
			ProviderName:             envOrDefault("PLATFORM_EGRESS_SERVICE_PROVIDER_NAME", runtimeobservability.DefaultProviderName),
			CollectorConfigMapName:   envOrDefault("PLATFORM_EGRESS_SERVICE_COLLECTOR_CONFIGMAP_NAME", runtimeobservability.DefaultCollectorConfigMapName),
			CollectorConfigKey:       envOrDefault("PLATFORM_EGRESS_SERVICE_COLLECTOR_CONFIG_KEY", runtimeobservability.DefaultCollectorConfigKey),
			ProfileStoreName:         envOrDefault("PLATFORM_EGRESS_SERVICE_PROFILE_STORE_NAME", runtimeobservability.DefaultProfileStoreName),
			ProfileStoreKey:          envOrDefault("PLATFORM_EGRESS_SERVICE_PROFILE_STORE_KEY", runtimeobservability.DefaultProfileStoreKey),
			CollectorDeploymentName:  envOrDefault("PLATFORM_EGRESS_SERVICE_COLLECTOR_DEPLOYMENT_NAME", runtimeobservability.DefaultCollectorDeployment),
			LokiEndpoint:             envOrDefault("PLATFORM_EGRESS_SERVICE_LOKI_ENDPOINT", runtimeobservability.DefaultLokiEndpoint),
			EnableLLMHeaderLogExport: enableLLMHeaderLogs,
			TelemetrySyncInterval:    telemetrySyncInterval,
		},
	})
	must(err)

	listener, err := net.Listen("tcp", addr)
	must(err)
	grpcServer := grpc.NewServer(grpc.StatsHandler(otelgrpc.NewServerHandler()))
	egressservicev1.RegisterEgressServiceServer(grpcServer, server)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(egressservicev1.EgressService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(grpcServer, healthServer)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcServer.Serve(listener) }()
	go server.RunRuntimeTelemetryReconciler(ctx)

	log.Printf("platform-egress-service listening on %s (namespace=%s, egressNamespace=%s, llm_header_logs=%t, telemetry_sync_interval=%s)", addr, namespace, egressNamespace, enableLLMHeaderLogs, telemetrySyncInterval)
	select {
	case err := <-serveErr:
		must(err)
	case <-ctx.Done():
		log.Println("shutting down platform-egress-service...")
		healthServer.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)
		healthServer.SetServingStatus(egressservicev1.EgressService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_NOT_SERVING)
		grpcServer.Stop()
	}
}

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func boolEnv(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func durationEnvOrDefault(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return fallback
	}
	return duration
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
