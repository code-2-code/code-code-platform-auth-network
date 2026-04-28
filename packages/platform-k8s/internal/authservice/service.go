package authservice

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	credentialcontract "code-code.internal/agent-runtime-contract/credential"
	credentialv1 "code-code.internal/go-contract/credential/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	"code-code.internal/platform-k8s/internal/authservice/credentials"
	"code-code.internal/platform-k8s/internal/authservice/oauth"
	"code-code.internal/platform-k8s/internal/egressauthpolicy"
	"code-code.internal/platform-k8s/internal/providerservice/providers"
	clioauthobservability "code-code.internal/platform-k8s/internal/supportservice/clidefinitions/observability"
	"code-code.internal/platform-k8s/internal/supportservice/references"
)

func NewServer(config Config) (*Server, error) {
	if config.Client == nil {
		return nil, fmt.Errorf("platformk8s/authservice: client is nil")
	}
	if strings.TrimSpace(config.Namespace) == "" {
		return nil, fmt.Errorf("platformk8s/authservice: namespace is empty")
	}
	if config.StatePool == nil {
		return nil, fmt.Errorf("platformk8s/authservice: state pool is nil")
	}
	if config.Reader == nil {
		config.Reader = config.Client
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	namespace := strings.TrimSpace(config.Namespace)
	runtimeNamespace := strings.TrimSpace(config.RuntimeNamespace)
	providerRepository, err := providers.NewProviderRepository(config.StatePool)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create provider repository: %w", err)
	}
	credentialStore := config.CredentialStore
	if credentialStore == nil && config.DomainOutbox != nil {
		credentialStore, err = credentials.NewPostgresResourceStore(config.StatePool, config.DomainOutbox, namespace)
		if err != nil {
			return nil, fmt.Errorf("platformk8s/authservice: create credential store: %w", err)
		}
	}
	if credentialStore == nil {
		credentialStore, err = credentials.NewKubernetesResourceStore(config.Client, namespace)
		if err != nil {
			return nil, fmt.Errorf("platformk8s/authservice: create credential store: %w", err)
		}
	}
	credentialMaterial := config.CredentialMaterial
	if credentialMaterial == nil {
		if config.CredentialEncryptor == nil {
			return nil, fmt.Errorf("platformk8s/authservice: credential material encryptor is nil")
		}
		credentialMaterial, err = credentials.NewPostgresCredentialMaterialStore(config.StatePool, namespace, config.CredentialEncryptor)
		if err != nil {
			return nil, fmt.Errorf("platformk8s/authservice: create credential material store: %w", err)
		}
	}
	credentialWriter, err := credentials.NewCredentialManagementServiceWithStores(config.Client, namespace, credentialStore, credentialMaterial)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create credential writer: %w", err)
	}
	credentialResolver, err := credentials.NewResolverWithStores(config.Client, namespace, credentialStore, credentialMaterial)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create credential resolver: %w", err)
	}
	materialReadPolicy := config.MaterialReadPolicy
	if materialReadPolicy == nil {
		materialReadPolicy, err = NewSupportCredentialMaterialReadAuthorizer()
		if err != nil {
			return nil, fmt.Errorf("platformk8s/authservice: create credential material read policy authorizer: %w", err)
		}
	}
	oauthImporter, err := credentials.NewOAuthCredentialImporterWithStores(config.Client, namespace, credentialStore, credentialMaterial)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create oauth importer: %w", err)
	}
	oauthSessionStore := config.OAuthSessionStore
	if oauthSessionStore == nil && config.DomainOutbox != nil {
		oauthSessionStore, err = oauth.NewPostgresAuthorizationSessionResourceStore(config.StatePool, config.DomainOutbox, namespace)
		if err != nil {
			return nil, fmt.Errorf("platformk8s/authservice: create oauth session store: %w", err)
		}
	}
	if oauthSessionStore == nil {
		oauthSessionStore, err = oauth.NewKubernetesAuthorizationSessionResourceStore(config.Client, config.Reader, namespace)
		if err != nil {
			return nil, fmt.Errorf("platformk8s/authservice: create oauth session store: %w", err)
		}
	}
	observer, err := clioauthobservability.RegisterWithCredentialStore(config.Client, namespace, providerRepository, credentialStore, credentialMaterial)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: register oauth observer: %w", err)
	}
	refreshRunner, err := credentials.NewRefreshRunner(credentials.RefreshRunnerConfig{
		Client:    config.Client,
		Namespace: namespace,
		Store:     credentialStore,
		Material:  credentialMaterial,
		Observer:  observer,
		Logger:    config.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create refresh runner: %w", err)
	}
	oauthSessions, err := NewOAuthSessionServer(OAuthSessionConfig{
		Client:                config.Client,
		APIReader:             config.Reader,
		Namespace:             namespace,
		ResourceStore:         oauthSessionStore,
		HostedCallbackBaseURL: config.HostedCallbackBaseURL,
		OAuthImporter:         oauthImporter,
		Observer:              observer,
	})
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: create oauth session server: %w", err)
	}
	headerRewritePolicies, err := egressauthpolicy.LoadDefaultCatalog()
	if err != nil {
		return nil, fmt.Errorf("platformk8s/authservice: load header rewrite policies: %w", err)
	}
	var agentSessions egressRuntimeContextClient
	if config.AgentSessionConn != nil {
		agentSessions = managementv1.NewAgentSessionManagementServiceClient(config.AgentSessionConn)
	}
	return &Server{
		client:                config.Client,
		reader:                config.Reader,
		namespace:             namespace,
		runtimeNamespace:      runtimeNamespace,
		credentialStore:       credentialStore,
		credentialMaterial:    credentialMaterial,
		materialReadPolicy:    materialReadPolicy,
		credentialWriter:      credentialWriter,
		credentialResolver:    credentialGrantResolver{base: credentialResolver},
		credentialRefChecker:  references.NewResourceReferenceChecker(providerRepository),
		providers:             providerRepository,
		oauthImporter:         oauthImporter,
		refreshRunner:         refreshRunner,
		oauthSessions:         oauthSessions,
		agentSessions:         agentSessions,
		headerRewritePolicies: headerRewritePolicies,
	}, nil
}

func (s *Server) OAuthSessionServer() *OAuthSessionServer {
	if s == nil {
		return nil
	}
	return s.oauthSessions
}

type credentialGrantResolver struct {
	base credentialcontract.Resolver
}

func (r credentialGrantResolver) Resolve(ctx context.Context, ref *credentialv1.CredentialGrantRef) (*credentialv1.ResolvedCredential, error) {
	if r.base == nil {
		return nil, fmt.Errorf("platformk8s/authservice: credential resolver is unavailable")
	}
	return r.base.Resolve(ctx, &credentialv1.CredentialRef{CredentialId: ref.GetGrantId()})
}
