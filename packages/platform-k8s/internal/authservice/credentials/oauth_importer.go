package credentials

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
	"code-code.internal/platform-k8s/internal/platform/resourcemeta"
	clioauth "code-code.internal/platform-k8s/internal/supportservice/clidefinitions/oauth"
	clisupport "code-code.internal/platform-k8s/internal/supportservice/clidefinitions/support"
	"google.golang.org/protobuf/types/known/timestamppb"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type oauthImportHTTPClientFactory interface {
	NewClient(ctx context.Context) (*http.Client, error)
}

// OAuthCredentialImporter stores CLI-owned OAuth artifacts as platform-owned credentials.
type OAuthCredentialImporter struct {
	credentials       *CredentialManagementService
	cliSupport        *clisupport.ManagementService
	httpClientFactory oauthImportHTTPClientFactory
	namespace         string
}

func NewOAuthCredentialImporterWithStores(
	client ctrlclient.Client,
	namespace string,
	store ResourceStore,
	materialStore CredentialMaterialStore,
) (*OAuthCredentialImporter, error) {
	credentials, err := NewCredentialManagementServiceWithStores(client, namespace, store, materialStore)
	if err != nil {
		return nil, err
	}
	return NewOAuthCredentialImporterWithCredentialService(client, namespace, credentials)
}

func NewOAuthCredentialImporterWithCredentialService(client ctrlclient.Client, namespace string, credentials *CredentialManagementService) (*OAuthCredentialImporter, error) {
	if credentials == nil {
		return nil, fmt.Errorf("platformk8s: credential service is nil")
	}
	cliSupport, err := clisupport.NewManagementService()
	if err != nil {
		return nil, err
	}
	return &OAuthCredentialImporter{
		credentials:       credentials,
		cliSupport:        cliSupport,
		httpClientFactory: outboundhttp.NewClientFactory(),
		namespace:         namespace,
	}, nil
}

// ImportOAuthCredential stores one OAuth artifact as one platform-owned OAuth credential.
func (i *OAuthCredentialImporter) ImportOAuthCredential(ctx context.Context, request *credentialcontract.OAuthImportRequest) (*credentialcontract.CredentialDefinition, error) {
	if err := credentialcontract.ValidateOAuthImportRequest(request); err != nil {
		return nil, err
	}
	if i == nil || i.credentials == nil || i.cliSupport == nil {
		return nil, fmt.Errorf("platformk8s: oauth credential importer is not initialized")
	}

	cliID := strings.TrimSpace(string(request.CliID))
	cli, err := i.cliSupport.Get(ctx, cliID)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: resolve cli support %q: %w", cliID, err)
	}
	projectedArtifact, err := clioauth.ResolveOAuthProjection(cli, &request.Artifact)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: resolve cli oauth projection for %q: %w", cliID, err)
	}

	credential, err := credentialFromOAuthImport(request, cli.GetVendorId(), *projectedArtifact)
	if err != nil {
		return nil, err
	}
	resource := credential.Resource(i.namespace)
	values, err := credential.MaterialValues()
	if err != nil {
		return nil, err
	}
	// Set OAuthMetadata on the definition; material remains in the material store.
	resource.Spec.Definition.KindMetadata = &credentialv1.CredentialDefinition_OauthMetadata{
		OauthMetadata: &credentialv1.OAuthMetadata{
			CliId: cliID,
		},
	}
	applyOAuthArtifactValues(values, request.CliID, *projectedArtifact)
	if err := i.applySpecializedOAuthValues(ctx, values, request, projectedArtifact); err != nil {
		return nil, err
	}

	resourcemeta.SetDisplayNameAnnotation(resource, request.DisplayName)

	if err := i.credentials.materialStore.WriteValues(ctx, resource.Name, values); err != nil {
		return nil, err
	}
	if err := i.credentials.store.Upsert(ctx, resource); err != nil {
		return nil, err
	}

	return &credentialcontract.CredentialDefinition{
		CredentialId: resource.Spec.Definition.CredentialId,
		DisplayName:  resource.Spec.Definition.DisplayName,
		Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
	}, nil
}

func credentialFromOAuthImport(
	request *credentialcontract.OAuthImportRequest,
	vendorID string,
	artifact credentialcontract.OAuthArtifact,
) (*Credential, error) {
	definition := &credentialv1.CredentialDefinition{
		CredentialId: request.CredentialID,
		DisplayName:  request.DisplayName,
		Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
		Purpose:      credentialv1.CredentialPurpose_CREDENTIAL_PURPOSE_DATA_PLANE,
		VendorId:     strings.TrimSpace(vendorID),
		KindMetadata: &credentialv1.CredentialDefinition_OauthMetadata{
			OauthMetadata: &credentialv1.OAuthMetadata{
				CliId: strings.TrimSpace(string(request.CliID)),
			},
		},
	}
	material := &credentialv1.ResolvedCredential{
		CredentialId: request.CredentialID,
		Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
		Material: &credentialv1.ResolvedCredential_Oauth{
			Oauth: &credentialv1.OAuthCredential{
				AccessToken:  strings.TrimSpace(artifact.AccessToken),
				TokenType:    strings.TrimSpace(artifact.TokenType),
				AccountId:    strings.TrimSpace(artifact.AccountID),
				Scopes:       append([]string(nil), artifact.Scopes...),
				RefreshToken: strings.TrimSpace(artifact.RefreshToken),
				IdToken:      strings.TrimSpace(artifact.IDToken),
			},
		},
	}
	if artifact.ExpiresAt != nil {
		material.GetOauth().ExpiresAt = timestamppb.New(artifact.ExpiresAt.UTC())
	}
	return NewCredential(definition, material)
}

func applyOAuthArtifactValues(values map[string]string, cliID credentialcontract.OAuthCLIID, artifact credentialcontract.OAuthArtifact) {
	if values == nil {
		return
	}
	values[materialKeyOAuthCLIID] = strings.ToLower(strings.TrimSpace(string(cliID)))
	if tokenType := strings.TrimSpace(artifact.TokenType); tokenType != "" {
		values[materialKeyTokenType] = tokenType
	}
	if accountID := strings.TrimSpace(artifact.AccountID); accountID != "" {
		values[materialKeyAccountID] = accountID
	}
	if token := strings.TrimSpace(artifact.RefreshToken); token != "" {
		values[materialKeyRefreshToken] = token
	}
	if token := strings.TrimSpace(artifact.IDToken); token != "" {
		values[materialKeyIDToken] = token
	}
	if raw := strings.TrimSpace(artifact.TokenResponseJSON); raw != "" {
		values[materialKeyTokenResponse] = raw
	}
	if email := strings.TrimSpace(artifact.AccountEmail); email != "" {
		values[materialKeyAccountEmail] = email
	}
}
