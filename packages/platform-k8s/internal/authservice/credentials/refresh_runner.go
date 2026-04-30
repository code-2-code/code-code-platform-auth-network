package credentials

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	clisupport "code-code.internal/platform-k8s/internal/platform/clidefinitions/support"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	refreshFailureBackoff = 5 * time.Minute
	maxRefreshRetries     = 3
	retryBackoffBase      = 2 * time.Second

	ConditionOAuthRefreshReady = "OAuthRefreshReady"
)

type oauthConditionUpdate struct {
	conditionType string
	status        metav1.ConditionStatus
	reason        string
	message       string
}

type refreshAttemptRecorder interface {
	RecordRefreshAttempt(cliID, credentialID, result string)
}

// RefreshRunner scans OAuth credentials and refreshes tokens that are near expiry.
type RefreshRunner struct {
	client     ctrlclient.Client
	namespace  string
	store      ResourceStore
	material   CredentialMaterialStore
	refreshers map[string]OAuthTokenRefresher
	cliSupport *clisupport.ManagementService
	observer   refreshAttemptRecorder
	logger     *slog.Logger
}

// RefreshRunnerConfig groups dependencies for the RefreshRunner.
type RefreshRunnerConfig struct {
	Client     ctrlclient.Client
	Namespace  string
	Store      ResourceStore
	Material   CredentialMaterialStore
	Refreshers []OAuthTokenRefresher
	Observer   refreshAttemptRecorder
	Logger     *slog.Logger
}

// EnsureFreshResult describes one ensure-fresh execution outcome.
type EnsureFreshResult struct {
	Outcome          string
	Refreshed        bool
	ExpiresAt        *time.Time
	NextRefreshAfter *time.Time
	LastRefreshedAt  *time.Time
}

// NewRefreshRunner creates one OAuth refresh runner.
func NewRefreshRunner(config RefreshRunnerConfig) (*RefreshRunner, error) {
	if config.Client == nil {
		return nil, fmt.Errorf("credentials: refresh runner client is nil")
	}
	if config.Namespace == "" {
		return nil, fmt.Errorf("credentials: refresh runner namespace is empty")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if len(config.Refreshers) == 0 {
		config.Refreshers = DefaultOAuthTokenRefreshers()
	}
	cliSupport, err := clisupport.NewManagementService()
	if err != nil {
		return nil, err
	}
	store := config.Store
	if store == nil {
		store, err = NewKubernetesResourceStore(config.Client, config.Namespace)
		if err != nil {
			return nil, err
		}
	}
	materialStore := config.Material
	if materialStore == nil {
		return nil, fmt.Errorf("credentials: refresh runner material store is nil")
	}
	refreshers := make(map[string]OAuthTokenRefresher, len(config.Refreshers))
	for _, r := range config.Refreshers {
		cliID := strings.TrimSpace(r.CliID())
		if cliID == "" {
			continue
		}
		refreshers[cliID] = r
	}
	return &RefreshRunner{
		client:     config.Client,
		namespace:  config.Namespace,
		store:      store,
		material:   materialStore,
		refreshers: refreshers,
		cliSupport: cliSupport,
		observer:   config.Observer,
		logger:     config.Logger,
	}, nil
}

// RunAll refreshes all OAuth credentials that are within the configured refresh window.
func (r *RefreshRunner) RunAll(ctx context.Context) error {
	now := time.Now().UTC()

	items, err := r.store.List(ctx)
	if err != nil {
		return fmt.Errorf("credentials: list credential definitions: %w", err)
	}

	slices.SortFunc(items, func(a, b platformv1alpha1.CredentialDefinitionResource) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	})

	var errs []error
	for i := range items {
		if _, err := r.runOne(ctx, &items[i], now, runOneOptions{}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *RefreshRunner) runOne(ctx context.Context, resource *platformv1alpha1.CredentialDefinitionResource, now time.Time, options runOneOptions) (*EnsureFreshResult, error) {
	if resource == nil || resource.DeletionTimestamp != nil || resource.Spec.Definition == nil {
		return &EnsureFreshResult{Outcome: "fresh"}, nil
	}
	definition := resource.Spec.Definition
	if definition.CredentialId == "" {
		definition.CredentialId = resource.Name
	}
	if definition.Kind != credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH {
		return &EnsureFreshResult{Outcome: "fresh"}, nil
	}

	oauth := definition.GetOauthMetadata()
	key := types.NamespacedName{Namespace: resource.Namespace, Name: resource.Name}
	if oauth == nil || oauth.CliId == "" {
		err := fmt.Errorf("oauth metadata and cli_id are required")
		updateErr := r.updateOAuthStatus(ctx, key, resource.Generation, nil, refreshConditionUpdate(err))
		if updateErr != nil {
			return nil, updateErr
		}
		if options.strict {
			return nil, err
		}
		return &EnsureFreshResult{Outcome: "fresh"}, nil
	}
	refresher, ok := r.refreshers[oauth.CliId]
	if !ok {
		err := fmt.Errorf("oauth refresher %q is not registered", oauth.CliId)
		updateErr := r.updateOAuthStatus(ctx, key, resource.Generation, nil, refreshConditionUpdate(err))
		if updateErr != nil {
			return nil, updateErr
		}
		if options.strict {
			return nil, err
		}
		return &EnsureFreshResult{Outcome: "fresh"}, nil
	}

	values, err := r.material.ReadValues(ctx, definition.CredentialId)
	if err != nil {
		updateErr := r.updateOAuthStatus(ctx, key, resource.Generation, nil, refreshConditionUpdate(err))
		if updateErr != nil {
			return nil, updateErr
		}
		if options.strict {
			return nil, err
		}
		return &EnsureFreshResult{Outcome: "fresh"}, nil
	}

	expiresAt, needs, nextRefreshAfter, scheduleErr := r.evaluateRefresh(values, resource.Status.OAuth, refresher, now, options)
	if scheduleErr != nil {
		updateErr := r.updateOAuthStatus(ctx, key, resource.Generation, nil, refreshConditionUpdate(scheduleErr))
		if updateErr != nil {
			return nil, updateErr
		}
		if options.strict {
			return nil, scheduleErr
		}
		return &EnsureFreshResult{Outcome: "fresh", ExpiresAt: expiresAt}, nil
	}

	if !needs {
		status := r.oauthStatusFromDefinition(definition, resource.Status.OAuth)
		if nextRefreshAfter != nil {
			status.NextRefreshAfter = &metav1.Time{Time: *nextRefreshAfter}
		}
		if err := r.updateOAuthStatus(ctx, key, resource.Generation, status, refreshConditionUpdate(nil)); err != nil {
			return nil, err
		}
		return &EnsureFreshResult{
			Outcome:          "fresh",
			Refreshed:        false,
			ExpiresAt:        expiresAt,
			NextRefreshAfter: nextRefreshAfter,
			LastRefreshedAt:  timePointerFromMeta(status.LastRefreshedAt),
		}, nil
	}

	result, err := r.refreshCredential(ctx, key, resource.Generation, definition, oauth, resource.Status.OAuth, refresher, now)
	if err != nil && !options.strict {
		return result, nil
	}
	return result, err
}
