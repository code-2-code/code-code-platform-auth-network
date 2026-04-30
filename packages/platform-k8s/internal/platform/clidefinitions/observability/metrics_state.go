package observability

import (
	"context"
	"fmt"
	"strings"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"code-code.internal/platform-k8s/internal/authservice/credentials"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type stateObserver struct {
	client          ctrlclient.Client
	namespace       string
	credentialStore credentials.ResourceStore
	materialStore   credentials.CredentialMaterialStore

	sessionInflight      otelmetric.Float64ObservableGauge
	credentialExpiry     otelmetric.Float64ObservableGauge
	nextRefresh          otelmetric.Float64ObservableGauge
	lastRefreshed        otelmetric.Float64ObservableGauge
	credentialGeneration otelmetric.Float64ObservableGauge
	refreshReady         otelmetric.Float64ObservableGauge
}

func registerStateObserver(
	meter otelmetric.Meter,
	client ctrlclient.Client,
	namespace string,
	credentialStore credentials.ResourceStore,
	materialStore credentials.CredentialMaterialStore,
) (*stateObserver, otelmetric.Registration, error) {
	state := &stateObserver{
		client:          client,
		namespace:       namespace,
		credentialStore: credentialStore,
		materialStore:   materialStore,
	}
	var err error
	state.sessionInflight, err = newObserverObservableGauge(
		meter,
		sessionInflightMetric,
		"Current number of non-terminal CLI OAuth authorization sessions.",
	)
	if err != nil {
		return nil, nil, err
	}
	state.credentialExpiry, err = newObserverObservableGauge(
		meter,
		credentialExpiryMetric,
		"Credential-scoped OAuth access token expiry timestamp.",
	)
	if err != nil {
		return nil, nil, err
	}
	state.nextRefresh, err = newObserverObservableGauge(
		meter,
		nextRefreshMetric,
		"Credential-scoped OAuth next refresh timestamp.",
	)
	if err != nil {
		return nil, nil, err
	}
	state.lastRefreshed, err = newObserverObservableGauge(
		meter,
		lastRefreshedMetric,
		"Credential-scoped OAuth last refreshed timestamp.",
	)
	if err != nil {
		return nil, nil, err
	}
	state.credentialGeneration, err = newObserverObservableGauge(
		meter,
		credentialGenerationMetric,
		"Credential-scoped OAuth credential generation.",
	)
	if err != nil {
		return nil, nil, err
	}
	state.refreshReady, err = newObserverObservableGauge(
		meter,
		refreshReadyMetric,
		"Whether provider OAuth refresh status is ready (1=true, 0=false).",
	)
	if err != nil {
		return nil, nil, err
	}
	registration, err := meter.RegisterCallback(
		state.observe,
		state.sessionInflight,
		state.credentialExpiry,
		state.nextRefresh,
		state.lastRefreshed,
		state.credentialGeneration,
		state.refreshReady,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("platformk8s/clidefinitions/observability: register state observer: %w", err)
	}
	return state, registration, nil
}

func (c *stateObserver) observe(ctx context.Context, observer otelmetric.Observer) error {
	c.observeSessions(ctx, observer)
	c.observeCredentials(ctx, observer)
	return nil
}

func (c *stateObserver) observeSessions(ctx context.Context, observer otelmetric.Observer) {
	list := &platformv1alpha1.OAuthAuthorizationSessionResourceList{}
	if err := c.client.List(ctx, list, ctrlclient.InNamespace(c.namespace)); err != nil {
		return
	}
	counts := map[string]float64{}
	for i := range list.Items {
		item := &list.Items[i]
		if isTerminalSessionPhase(item.Status.Phase) {
			continue
		}
		key := strings.TrimSpace(item.Spec.CliID) + "|" + normalizeFlow(item.Spec.Flow)
		counts[key]++
	}
	for key, value := range counts {
		parts := strings.SplitN(key, "|", 2)
		observer.ObserveFloat64(c.sessionInflight, value, otelmetric.WithAttributes(
			attribute.String("cli_id", parts[0]),
			attribute.String("flow", parts[1]),
		))
	}
}

func (c *stateObserver) observeCredentials(ctx context.Context, observer otelmetric.Observer) {
	items, err := c.listCredentialResources(ctx)
	if err != nil {
		return
	}
	for i := range items {
		resource := &items[i]
		definition := resource.Spec.Definition
		if definition == nil || definition.GetKind() != credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH {
			continue
		}
		credentialID := strings.TrimSpace(definition.GetCredentialId())
		if credentialID == "" {
			credentialID = resource.Name
		}
		cliID := strings.TrimSpace(definition.GetOauthMetadata().GetCliId())
		if credentialID == "" || cliID == "" {
			continue
		}
		attrs := otelmetric.WithAttributes(
			attribute.String("cli_id", cliID),
			attribute.String("credential_id", credentialID),
		)
		if expiresAt, ok := c.materialExpiry(ctx, credentialID); ok {
			observer.ObserveFloat64(c.credentialExpiry, float64(expiresAt.Unix()), attrs)
		}
		if status := resource.Status.OAuth; status != nil {
			observer.ObserveFloat64(c.credentialGeneration, float64(status.CredentialGeneration), attrs)
			if status.NextRefreshAfter != nil && !status.NextRefreshAfter.IsZero() {
				observer.ObserveFloat64(c.nextRefresh, float64(status.NextRefreshAfter.Unix()), attrs)
			}
			if status.LastRefreshedAt != nil && !status.LastRefreshedAt.IsZero() {
				observer.ObserveFloat64(c.lastRefreshed, float64(status.LastRefreshedAt.Unix()), attrs)
			}
		}
		observer.ObserveFloat64(c.refreshReady, conditionGauge(resource.Status.Conditions, conditionOAuthRefreshReady), attrs)
	}
}

func (c *stateObserver) listCredentialResources(ctx context.Context) ([]platformv1alpha1.CredentialDefinitionResource, error) {
	if c.credentialStore != nil {
		return c.credentialStore.List(ctx)
	}
	list := &platformv1alpha1.CredentialDefinitionResourceList{}
	if err := c.client.List(ctx, list, ctrlclient.InNamespace(c.namespace)); err != nil {
		return nil, err
	}
	return append([]platformv1alpha1.CredentialDefinitionResource(nil), list.Items...), nil
}

func (c *stateObserver) materialExpiry(ctx context.Context, credentialID string) (time.Time, bool) {
	if c.materialStore == nil || strings.TrimSpace(credentialID) == "" {
		return time.Time{}, false
	}
	values, err := c.materialStore.ReadValues(ctx, credentialID)
	if err != nil {
		return time.Time{}, false
	}
	expiresAt, err := credentials.ExpiresAtFromMaterialValues(values)
	if err != nil {
		return time.Time{}, false
	}
	if expiresAt == nil {
		return time.Time{}, false
	}
	return expiresAt.UTC(), true
}
