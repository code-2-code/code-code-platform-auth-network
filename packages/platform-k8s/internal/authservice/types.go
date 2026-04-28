package authservice

import (
	"context"
	"log/slog"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	"code-code.internal/platform-k8s/internal/authservice/credentials"
	"code-code.internal/platform-k8s/internal/authservice/oauth"
	"code-code.internal/platform-k8s/internal/egressauthpolicy"
	"code-code.internal/platform-k8s/internal/platform/domainevents"
	"code-code.internal/platform-k8s/internal/providerservice/providers"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type Config struct {
	Client                ctrlclient.Client
	Reader                ctrlclient.Reader
	Namespace             string
	RuntimeNamespace      string
	StatePool             *pgxpool.Pool
	DomainOutbox          *domainevents.Outbox
	CredentialStore       credentials.ResourceStore
	CredentialMaterial    credentials.CredentialMaterialStore
	CredentialEncryptor   credentials.CredentialMaterialEncryptor
	MaterialReadPolicy    CredentialMaterialReadAuthorizer
	OAuthSessionStore     oauth.AuthorizationSessionResourceStore
	HostedCallbackBaseURL string
	AgentSessionConn      grpc.ClientConnInterface
	Logger                *slog.Logger
}

type Server struct {
	authv1.UnimplementedAuthServiceServer

	client                ctrlclient.Client
	reader                ctrlclient.Reader
	namespace             string
	runtimeNamespace      string
	credentialStore       credentials.ResourceStore
	credentialMaterial    credentials.CredentialMaterialStore
	materialReadPolicy    CredentialMaterialReadAuthorizer
	credentialWriter      *credentials.CredentialManagementService
	credentialResolver    egressCredentialResolver
	credentialRefChecker  credentials.CredentialReferenceChecker
	providers             providers.Store
	oauthImporter         credentialcontract.OAuthCredentialImporter
	refreshRunner         *credentials.RefreshRunner
	oauthSessions         *OAuthSessionServer
	agentSessions         egressRuntimeContextClient
	headerRewritePolicies *egressauthpolicy.Catalog
}

type egressRuntimeContextClient interface {
	ResolveAgentRunRuntimeContext(context.Context, *managementv1.ResolveAgentRunRuntimeContextRequest, ...grpc.CallOption) (*managementv1.ResolveAgentRunRuntimeContextResponse, error)
}

type egressCredentialResolver interface {
	Resolve(context.Context, *credentialv1.CredentialGrantRef) (*credentialv1.ResolvedCredential, error)
}

type ClientConfig struct {
	Conn grpc.ClientConnInterface
}

type Client struct {
	auth authv1.AuthServiceClient
}
