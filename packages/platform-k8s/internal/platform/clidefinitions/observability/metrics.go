package observability

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"code-code.internal/platform-k8s/internal/authservice/credentials"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	sessionStartsMetric        = "gen_ai.provider.cli.oauth.session.starts.total"
	sessionTerminalMetric      = "gen_ai.provider.cli.oauth.session.terminal.total"
	sessionInflightMetric      = "gen_ai.provider.cli.oauth.session.inflight"
	sessionDurationMetric      = "gen_ai.provider.cli.oauth.session.duration.seconds"
	credentialExpiryMetric     = "gen_ai.provider.cli.oauth.credential.expiry.timestamp.seconds"
	nextRefreshMetric          = "gen_ai.provider.cli.oauth.next.refresh.timestamp.seconds"
	lastRefreshedMetric        = "gen_ai.provider.cli.oauth.last.refreshed.timestamp.seconds"
	credentialGenerationMetric = "gen_ai.provider.cli.oauth.credential.generation"
	refreshReadyMetric         = "gen_ai.provider.cli.oauth.refresh.ready"
	refreshAttemptsMetric      = "gen_ai.provider.cli.oauth.refresh.attempts.total"

	conditionOAuthRefreshReady = "OAuthRefreshReady"
)

type Observer struct {
	client    ctrlclient.Client
	namespace string

	sessionStarts     otelmetric.Int64Counter
	sessionTerminal   otelmetric.Int64Counter
	sessionDuration   otelmetric.Float64Histogram
	refreshAttempts   otelmetric.Int64Counter
	stateRegistration otelmetric.Registration
}

var (
	registerMetricsOnce sync.Once
	registeredObserver  *Observer
	registerMetricsErr  error
)

func RegisterWithCredentialStore(
	client ctrlclient.Client,
	namespace string,
	credentialStore credentials.ResourceStore,
	materialStore credentials.CredentialMaterialStore,
) (*Observer, error) {
	registerMetricsOnce.Do(func() {
		if client == nil {
			registerMetricsErr = fmt.Errorf("platformk8s/clidefinitions/observability: client is nil")
			return
		}
		if materialStore == nil {
			registerMetricsErr = fmt.Errorf("platformk8s/clidefinitions/observability: credential material store is nil")
			return
		}
		namespace = strings.TrimSpace(namespace)
		if namespace == "" {
			registerMetricsErr = fmt.Errorf("platformk8s/clidefinitions/observability: namespace is empty")
			return
		}

		meter := otel.Meter("platform-k8s/clidefinitions/observability")
		sessionStarts, err := newObserverCounter(
			meter,
			sessionStartsMetric,
			"Count of started CLI OAuth authorization sessions.",
		)
		if err != nil {
			registerMetricsErr = err
			return
		}
		sessionTerminal, err := newObserverCounter(
			meter,
			sessionTerminalMetric,
			"Count of terminal CLI OAuth authorization sessions.",
		)
		if err != nil {
			registerMetricsErr = err
			return
		}
		sessionDuration, err := meter.Float64Histogram(
			sessionDurationMetric,
			otelmetric.WithDescription("Duration of terminal CLI OAuth authorization sessions."),
			otelmetric.WithUnit("s"),
		)
		if err != nil {
			registerMetricsErr = fmt.Errorf("platformk8s/clidefinitions/observability: create histogram %q: %w", sessionDurationMetric, err)
			return
		}
		refreshAttempts, err := newObserverCounter(
			meter,
			refreshAttemptsMetric,
			"Count of CLI OAuth refresh attempts scoped to bound providers.",
		)
		if err != nil {
			registerMetricsErr = err
			return
		}
		_, registration, err := registerStateObserver(meter, client, namespace, credentialStore, materialStore)
		if err != nil {
			registerMetricsErr = err
			return
		}

		registeredObserver = &Observer{
			client:            client,
			namespace:         namespace,
			sessionStarts:     sessionStarts,
			sessionTerminal:   sessionTerminal,
			sessionDuration:   sessionDuration,
			refreshAttempts:   refreshAttempts,
			stateRegistration: registration,
		}
	})
	if registerMetricsErr != nil {
		return nil, registerMetricsErr
	}
	return registeredObserver, nil
}

func newObserverCounter(meter otelmetric.Meter, name string, description string) (otelmetric.Int64Counter, error) {
	counter, err := meter.Int64Counter(name, otelmetric.WithDescription(description), otelmetric.WithUnit("1"))
	if err != nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions/observability: create counter %q: %w", name, err)
	}
	return counter, nil
}

func newObserverObservableGauge(meter otelmetric.Meter, name string, description string) (otelmetric.Float64ObservableGauge, error) {
	gauge, err := meter.Float64ObservableGauge(name, otelmetric.WithDescription(description))
	if err != nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions/observability: create observable gauge %q: %w", name, err)
	}
	return gauge, nil
}

func (o *Observer) RecordSessionStarted(cliID string, flow credentialv1.OAuthAuthorizationFlow) {
	if o == nil {
		return
	}
	o.sessionStarts.Add(context.Background(), 1, otelmetric.WithAttributes(
		attribute.String("cli_id", strings.TrimSpace(cliID)),
		attribute.String("flow", normalizeFlowFromProto(flow)),
	))
}

func (o *Observer) RecordSessionTerminal(cliID string, flow platformv1alpha1.OAuthAuthorizationSessionFlow, phase platformv1alpha1.OAuthAuthorizationSessionPhase, startedAt, endedAt time.Time) {
	if o == nil {
		return
	}
	labels := []string{
		strings.TrimSpace(cliID),
		normalizeFlow(flow),
		normalizeTerminalPhase(phase),
	}
	ctx := context.Background()
	attrs := otelmetric.WithAttributes(
		attribute.String("cli_id", labels[0]),
		attribute.String("flow", labels[1]),
		attribute.String("terminal_phase", labels[2]),
	)
	o.sessionTerminal.Add(ctx, 1, attrs)
	if !startedAt.IsZero() && !endedAt.IsZero() && endedAt.After(startedAt) {
		o.sessionDuration.Record(ctx, endedAt.Sub(startedAt).Seconds(), attrs)
	}
}

func (o *Observer) RecordRefreshAttempt(cliID, credentialID, result string) {
	if o == nil {
		return
	}
	trimmedCredentialID := strings.TrimSpace(credentialID)
	trimmedResult := strings.TrimSpace(result)
	if trimmedCredentialID == "" || trimmedResult == "" {
		return
	}
	trimmedCliID := strings.TrimSpace(cliID)
	o.refreshAttempts.Add(context.Background(), 1, otelmetric.WithAttributes(
		attribute.String("cli_id", trimmedCliID),
		attribute.String("credential_id", trimmedCredentialID),
		attribute.String("result", trimmedResult),
	))
}
