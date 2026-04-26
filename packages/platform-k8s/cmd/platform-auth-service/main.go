package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	oauthv1 "code-code.internal/go-contract/platform/oauth/v1"
	platformk8s "code-code.internal/platform-k8s"
	"code-code.internal/platform-k8s/authservice"
	"code-code.internal/platform-k8s/domainevents"
	"code-code.internal/platform-k8s/internal/triggerhttp"
	"code-code.internal/platform-k8s/state"
	"code-code.internal/platform-k8s/telemetry"
	"code-code.internal/platform-k8s/temporalruntime"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	temporalworker "go.temporal.io/sdk/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {
	namespace := envOrDefault("PLATFORM_AUTH_SERVICE_NAMESPACE", "code-code")
	grpcAddr := envOrDefault("PLATFORM_AUTH_SERVICE_GRPC_ADDR", ":8081")
	httpAddr := envOrDefault("PLATFORM_AUTH_SERVICE_HTTP_ADDR", ":8080")
	oauthCallbackBaseURL := envOrDefault("PLATFORM_AUTH_SERVICE_OAUTH_CALLBACK_BASE_URL", "")
	agentRuntimeAddr := envOrDefault("PLATFORM_AUTH_SERVICE_AGENT_RUNTIME_GRPC_ADDR", "platform-agent-runtime-service:8081")
	domainEventsNATSURL := envOrDefault("PLATFORM_AUTH_SERVICE_DOMAIN_EVENTS_NATS_URL", "")
	databaseURL := firstEnv("PLATFORM_DATABASE_URL", "PLATFORM_AUTH_SERVICE_DATABASE_URL")

	scheme := runtime.NewScheme()
	must(corev1.AddToScheme(scheme))
	must(platformk8s.AddToScheme(scheme))

	telemetryShutdown, err := telemetry.Setup(context.Background(), envOrDefault("OTEL_SERVICE_NAME", "platform-auth-service"))
	must(err)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := telemetryShutdown(shutdownCtx); err != nil {
			log.Printf("shutdown telemetry failed: %v", err)
		}
	}()
	config := ctrl.GetConfigOrDie()
	directClient, err := ctrlclient.New(config, ctrlclient.Options{Scheme: scheme})
	must(err)
	statePool, err := state.OpenPostgres(context.Background(), databaseURL, "platform-auth-service")
	must(err)
	defer statePool.Close()
	outbox, err := domainevents.NewOutbox(statePool, "platform-auth-service")
	must(err)
	agentRuntimeConn, err := grpc.NewClient(agentRuntimeAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	must(err)
	defer func() { _ = agentRuntimeConn.Close() }()

	server, err := authservice.NewServer(authservice.Config{
		Client:                directClient,
		Reader:                directClient,
		Namespace:             namespace,
		StatePool:             statePool,
		DomainOutbox:          outbox,
		HostedCallbackBaseURL: oauthCallbackBaseURL,
		AgentSessionConn:      agentRuntimeConn,
	})
	must(err)
	temporalConfig := temporalruntime.ConfigFromEnv(authservice.TemporalTaskQueue)
	temporalRuntime, err := temporalruntime.Start(context.Background(), temporalConfig, func(worker temporalworker.Worker) error {
		return authservice.RegisterTemporalWorkflows(worker, server)
	}, authservice.EnsureTemporalSchedules)
	must(err)
	defer temporalRuntime.Stop()
	oauthCallbackServer, err := authservice.NewOAuthCallbackServer(server.OAuthSessionServer().SessionManager())
	must(err)
	triggerServer, err := triggerhttp.NewServer(triggerhttp.Config{
		Logger: slog.Default(),
		Actions: map[string]triggerhttp.ActionFunc{
			"refresh-oauth-due": func(ctx context.Context, _ triggerhttp.Request) (any, error) {
				response, err := server.RefreshOAuthDue(ctx, &authv1.RefreshOAuthDueRequest{})
				if err != nil {
					return nil, err
				}
				return map[string]string{"status": response.GetStatus()}, nil
			},
			"scan-oauth-sessions": func(ctx context.Context, _ triggerhttp.Request) (any, error) {
				response, err := server.ScanOAuthSessions(ctx, &authv1.ScanOAuthSessionsRequest{})
				if err != nil {
					return nil, err
				}
				return map[string]string{"status": response.GetStatus()}, nil
			},
		},
	})
	must(err)

	listener, err := net.Listen("tcp", grpcAddr)
	must(err)
	httpListener, err := net.Listen("tcp", httpAddr)
	must(err)
	httpServer := &http.Server{Handler: triggerServer}
	grpcServer := grpc.NewServer(grpc.StatsHandler(otelgrpc.NewServerHandler()))
	authv1.RegisterAuthServiceServer(grpcServer, server)
	oauthv1.RegisterOAuthSessionServiceServer(grpcServer, server.OAuthSessionServer())
	oauthv1.RegisterOAuthCallbackServiceServer(grpcServer, oauthCallbackServer)

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(authv1.AuthService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(oauthv1.OAuthSessionService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(oauthv1.OAuthCallbackService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(grpcServer, healthServer)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if domainEventsNATSURL != "" {
		publisher, err := domainevents.NewPublisher(outbox, domainevents.PublisherConfig{
			NATSURL:    domainEventsNATSURL,
			ClientName: "platform-auth-service-domain-publisher",
		})
		must(err)
		defer publisher.Close()
		go func() { _ = publisher.Run(ctx) }()
		must(server.StartDomainEventConsumers(ctx, statePool, domainEventsNATSURL))
		log.Printf("domain event bus enabled (nats=%s)", domainEventsNATSURL)
	}
	serveErr := make(chan error, 2)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			serveErr <- err
		}
	}()
	go func() {
		if err := httpServer.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	go func() {
		<-ctx.Done()
		healthServer.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)
		healthServer.SetServingStatus(authv1.AuthService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_NOT_SERVING)
		healthServer.SetServingStatus(oauthv1.OAuthSessionService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_NOT_SERVING)
		healthServer.SetServingStatus(oauthv1.OAuthCallbackService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("platform-auth-service starting (namespace=%s grpc=%s http=%s temporal=%s/%s)", namespace, grpcAddr, httpAddr, temporalConfig.Address, temporalConfig.TaskQueue)
	select {
	case err := <-serveErr:
		must(err)
	case <-ctx.Done():
	}
}

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		value := os.Getenv(key)
		if value != "" {
			return value
		}
	}
	return ""
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
