package oauth

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const defaultTerminalRetention = 30 * time.Minute

type SessionReconciler struct {
	client            ctrlclient.Client
	namespace         string
	resourceStore     AuthorizationSessionResourceStore
	executor          *SessionExecutor
	sessionStore      *OAuthSessionSecretStore
	observer          SessionObserver
	logger            *slog.Logger
	now               func() time.Time
	terminalRetention time.Duration
}

type SessionReconcilerConfig struct {
	Client            ctrlclient.Client
	Namespace         string
	ResourceStore     AuthorizationSessionResourceStore
	Executor          *SessionExecutor
	SessionStore      *OAuthSessionSecretStore
	Observer          SessionObserver
	Logger            *slog.Logger
	Now               func() time.Time
	TerminalRetention time.Duration
}

func NewSessionReconciler(config SessionReconcilerConfig) (*SessionReconciler, error) {
	if config.Client == nil {
		return nil, fmt.Errorf("platformk8s/oauth: reconciler client is nil")
	}
	if strings.TrimSpace(config.Namespace) == "" {
		return nil, fmt.Errorf("platformk8s/oauth: reconciler namespace is empty")
	}
	if config.Executor == nil {
		return nil, fmt.Errorf("platformk8s/oauth: reconciler executor is nil")
	}
	if config.SessionStore == nil {
		return nil, fmt.Errorf("platformk8s/oauth: reconciler session store is nil")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.TerminalRetention <= 0 {
		config.TerminalRetention = defaultTerminalRetention
	}
	resourceStore := config.ResourceStore
	if resourceStore == nil {
		var err error
		resourceStore, err = NewKubernetesAuthorizationSessionResourceStore(config.Client, config.Client, config.Namespace)
		if err != nil {
			return nil, err
		}
	}
	return &SessionReconciler{
		client:            config.Client,
		namespace:         strings.TrimSpace(config.Namespace),
		resourceStore:     resourceStore,
		executor:          config.Executor,
		sessionStore:      config.SessionStore,
		observer:          config.Observer,
		logger:            config.Logger,
		now:               config.Now,
		terminalRetention: config.TerminalRetention,
	}, nil
}
