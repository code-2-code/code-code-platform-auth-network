package authservice

import (
	"context"
	"fmt"
	"strings"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func NewClient(config ClientConfig) *Client {
	if config.Conn == nil {
		return &Client{}
	}
	return &Client{auth: authv1.NewAuthServiceClient(config.Conn)}
}

func (c *Client) ListCredentials(ctx context.Context) ([]*managementv1.CredentialView, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	response, err := c.auth.ListCredentials(ctx, &authv1.ListCredentialsRequest{})
	if err != nil {
		return nil, err
	}
	return response.GetItems(), nil
}

func (c *Client) CredentialExists(ctx context.Context, credentialID string) (bool, error) {
	items, err := c.ListCredentials(ctx)
	if err != nil {
		return false, err
	}
	credentialID = strings.TrimSpace(credentialID)
	for _, item := range items {
		if strings.TrimSpace(item.GetCredentialId()) == credentialID {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) RenameCredential(ctx context.Context, credentialID string, displayName string) (*managementv1.CredentialView, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	response, err := c.auth.RenameCredential(ctx, &authv1.RenameCredentialRequest{
		CredentialId: strings.TrimSpace(credentialID),
		DisplayName:  strings.TrimSpace(displayName),
	})
	if err != nil {
		return nil, err
	}
	return response.GetCredential(), nil
}

func (c *Client) CreateAPIKeyCredential(ctx context.Context, request *authv1.CreateAPIKeyCredentialRequest) (*managementv1.CredentialView, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	response, err := c.auth.CreateAPIKeyCredential(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.GetCredential(), nil
}

func (c *Client) UpdateAPIKeyCredential(ctx context.Context, request *authv1.UpdateAPIKeyCredentialRequest) (*managementv1.CredentialView, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	response, err := c.auth.UpdateAPIKeyCredential(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.GetCredential(), nil
}

func (c *Client) CreateSessionCredential(ctx context.Context, request *authv1.CreateSessionCredentialRequest) (*managementv1.CredentialView, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	response, err := c.auth.CreateSessionCredential(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.GetCredential(), nil
}

func (c *Client) UpdateSessionCredential(ctx context.Context, request *authv1.UpdateSessionCredentialRequest) (*managementv1.CredentialView, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	response, err := c.auth.UpdateSessionCredential(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.GetCredential(), nil
}

func (c *Client) MergeCredentialMaterialValues(ctx context.Context, credentialID string, values map[string]string) error {
	if err := c.ready(); err != nil {
		return err
	}
	_, err := c.auth.MergeCredentialMaterialValues(ctx, &authv1.MergeCredentialMaterialValuesRequest{
		CredentialId: strings.TrimSpace(credentialID),
		Values:       cloneStringMap(values),
	})
	return err
}

func (c *Client) ReadCredentialMaterialFields(
	ctx context.Context,
	credentialID string,
	policyRef *authv1.CredentialMaterialReadPolicyRef,
	fieldIDs []string,
) (map[string]string, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	response, err := c.auth.ReadCredentialMaterialFields(ctx, &authv1.ReadCredentialMaterialFieldsRequest{
		CredentialId: strings.TrimSpace(credentialID),
		FieldIds:     append([]string(nil), fieldIDs...),
		PolicyRef:    policyRef,
	})
	if err != nil {
		return nil, err
	}
	return cloneStringMap(response.GetValues()), nil
}

func (c *Client) CreateOAuthCredential(ctx context.Context, request *authv1.CreateOAuthCredentialRequest) (*managementv1.CredentialView, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	response, err := c.auth.CreateOAuthCredential(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.GetCredential(), nil
}

func (c *Client) UpdateOAuthCredential(ctx context.Context, request *authv1.UpdateOAuthCredentialRequest) (*managementv1.CredentialView, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	response, err := c.auth.UpdateOAuthCredential(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.GetCredential(), nil
}

func (c *Client) DeleteCredential(ctx context.Context, credentialID string) error {
	if err := c.ready(); err != nil {
		return err
	}
	_, err := c.auth.DeleteCredential(ctx, &authv1.DeleteCredentialRequest{CredentialId: strings.TrimSpace(credentialID)})
	return err
}

func (c *Client) ImportOAuthCredential(ctx context.Context, request *credentialcontract.OAuthImportRequest) (*credentialcontract.CredentialDefinition, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	if request == nil {
		return nil, fmt.Errorf("platformk8s/authservice: oauth import request is nil")
	}
	response, err := c.auth.ImportOAuthCredential(ctx, &authv1.ImportOAuthCredentialRequest{
		CliId:        string(request.CliID),
		CredentialId: request.CredentialID,
		DisplayName:  request.DisplayName,
		Artifact:     oauthArtifactToProto(&request.Artifact),
	})
	if err != nil {
		return nil, err
	}
	return response.GetDefinition(), nil
}

func (c *Client) EnsureFresh(ctx context.Context, credentialID string, minTTLSeconds int64, forceRefresh bool) (*authv1.EnsureFreshResponse, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	return c.auth.EnsureFresh(ctx, &authv1.EnsureFreshRequest{
		CredentialId:  strings.TrimSpace(credentialID),
		MinTtlSeconds: minTTLSeconds,
		ForceRefresh:  forceRefresh,
	})
}

func (c *Client) RefreshOAuthDue(ctx context.Context) error {
	if err := c.ready(); err != nil {
		return err
	}
	_, err := c.auth.RefreshOAuthDue(ctx, &authv1.RefreshOAuthDueRequest{})
	return err
}

func (c *Client) ScanOAuthSessions(ctx context.Context) error {
	if err := c.ready(); err != nil {
		return err
	}
	_, err := c.auth.ScanOAuthSessions(ctx, &authv1.ScanOAuthSessionsRequest{})
	return err
}

func (c *Client) GetCredentialSubjectSummary(ctx context.Context, credentialID string) ([]*managementv1.CredentialSubjectSummaryFieldView, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	response, err := c.auth.GetCredentialSubjectSummary(ctx, &authv1.GetCredentialSubjectSummaryRequest{
		CredentialId: strings.TrimSpace(credentialID),
	})
	if err != nil {
		return nil, err
	}
	return response.GetFields(), nil
}

func oauthArtifactToProto(artifact *credentialcontract.OAuthArtifact) *authv1.OAuthArtifact {
	if artifact == nil {
		return nil
	}
	out := &authv1.OAuthArtifact{
		AccessToken:       artifact.AccessToken,
		RefreshToken:      artifact.RefreshToken,
		IdToken:           artifact.IDToken,
		TokenResponseJson: artifact.TokenResponseJSON,
		TokenType:         artifact.TokenType,
		AccountId:         artifact.AccountID,
		AccountEmail:      artifact.AccountEmail,
		Scopes:            append([]string(nil), artifact.Scopes...),
	}
	if artifact.ExpiresAt != nil {
		out.ExpiresAt = timestamppb.New(artifact.ExpiresAt.UTC())
	}
	return out
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func (c *Client) ready() error {
	if c == nil || c.auth == nil {
		return fmt.Errorf("platformk8s/authservice: auth service client is not configured")
	}
	return nil
}
