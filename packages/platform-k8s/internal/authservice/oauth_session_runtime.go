package authservice

import (
	"fmt"
	"log/slog"

	credentialcontract "code-code.internal/platform-contract/credential"
	"code-code.internal/platform-k8s/internal/authservice/oauth"
	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
	clisupport "code-code.internal/platform-k8s/internal/supportservice/clidefinitions/support"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type oauthSessionRuntime struct {
	sessionManager    *oauth.SessionManager
	sessionReconciler *oauth.SessionReconciler
	cliSupport        *clisupport.ManagementService
}

func assembleOAuthSessionRuntime(client ctrlclient.Client, reader ctrlclient.Reader, namespace string, resourceStore oauth.AuthorizationSessionResourceStore, hostedCallbackBaseURL string, importer credentialcontract.OAuthCredentialImporter, observer oauth.SessionObserver) (*oauthSessionRuntime, error) {
	sessionStore, err := oauth.NewOAuthSessionStore(client, reader, namespace)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create oauth session store: %w", err)
	}
	cliSupport, err := clisupport.NewManagementService()
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create cli support management for oauth session: %w", err)
	}
	codeFlowAuthorizers, err := oauth.RegisteredCodeFlowAuthorizers(oauth.CodeFlowAuthorizerFactoryConfig{
		SessionStore:      sessionStore,
		HTTPClientFactory: outboundhttp.NewClientFactory(),
	})
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create registered oauth authorizers: %w", err)
	}
	registry := NewOAuthAuthorizerRegistry(importer)
	for cliID, authorizer := range codeFlowAuthorizers {
		registry.RegisterCodeFlow(cliID, authorizer)
	}
	sessionManager, err := oauth.NewSessionManager(oauth.SessionManagerConfig{
		Client:                client,
		Reader:                reader,
		Namespace:             namespace,
		ResourceStore:         resourceStore,
		Registry:              registry,
		CLISupport:            cliSupport,
		HostedCallbackBaseURL: hostedCallbackBaseURL,
		SessionStore:          sessionStore,
		Observer:              observer,
	})
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create oauth session manager: %w", err)
	}
	executor, err := oauth.NewSessionExecutor(oauth.SessionExecutorConfig{
		Registry:     registry,
		Importer:     importer,
		SessionStore: sessionStore,
	})
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create oauth session executor: %w", err)
	}
	sessionReconciler, err := oauth.NewSessionReconciler(oauth.SessionReconcilerConfig{
		Client:        client,
		Namespace:     namespace,
		ResourceStore: resourceStore,
		Executor:      executor,
		SessionStore:  sessionStore,
		Observer:      observer,
		Logger:        slog.Default(),
	})
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create oauth session reconciler: %w", err)
	}
	return &oauthSessionRuntime{
		sessionManager:    sessionManager,
		sessionReconciler: sessionReconciler,
		cliSupport:        cliSupport,
	}, nil
}
