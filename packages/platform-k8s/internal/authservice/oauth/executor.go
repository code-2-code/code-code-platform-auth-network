package oauth

import (
	"context"
	"fmt"
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
)

type sessionImporter interface {
	ImportOAuthCredential(ctx context.Context, request *credentialcontract.OAuthImportRequest) (*credentialcontract.CredentialDefinition, error)
}

type SessionExecutor struct {
	registry     sessionAuthorizerRegistry
	importer     sessionImporter
	sessionStore *OAuthSessionSecretStore
}

type SessionExecutorConfig struct {
	Registry     sessionAuthorizerRegistry
	Importer     sessionImporter
	SessionStore *OAuthSessionSecretStore
}

func NewSessionExecutor(config SessionExecutorConfig) (*SessionExecutor, error) {
	if config.Registry == nil {
		return nil, fmt.Errorf("platformk8s/oauth: session executor registry is nil")
	}
	if config.Importer == nil {
		return nil, fmt.Errorf("platformk8s/oauth: session executor importer is nil")
	}
	if config.SessionStore == nil {
		return nil, fmt.Errorf("platformk8s/oauth: session executor session store is nil")
	}
	return &SessionExecutor{
		registry:     config.Registry,
		importer:     config.Importer,
		sessionStore: config.SessionStore,
	}, nil
}

func (e *SessionExecutor) ExchangeCode(ctx context.Context, session *platformv1alpha1.OAuthAuthorizationSessionResource) (*credentialcontract.OAuthArtifact, error) {
	if session == nil {
		return nil, fmt.Errorf("platformk8s/oauth: code exchange session is nil")
	}
	artifact, err := e.sessionStore.GetArtifactIfPresent(ctx, session.Spec.CliID, session.Spec.SessionID)
	if err != nil {
		return nil, err
	}
	if artifact != nil {
		return artifact, nil
	}
	payload, err := e.sessionStore.GetCodeCallback(ctx, session.Spec.CliID, session.Spec.SessionID)
	if err != nil {
		return nil, err
	}
	if payload.Error != "" {
		message := strings.TrimSpace(payload.ErrorDescription)
		if message == "" {
			message = strings.TrimSpace(payload.Error)
		}
		return nil, fmt.Errorf("platformk8s/oauth: oauth callback failed: %s", message)
	}
	authorizer, err := e.registry.CodeFlowAuthorizer(credentialcontract.OAuthCLIID(session.Spec.CliID))
	if err != nil {
		return nil, err
	}
	codeSession, err := e.sessionStore.GetCodeSession(ctx, session.Spec.CliID, session.Spec.SessionID)
	if err != nil {
		return nil, err
	}
	return authorizer.CompleteAuthorizationSession(ctx, &credentialcontract.OAuthAuthorizationExchange{
		CliID:               credentialcontract.OAuthCLIID(session.Spec.CliID),
		SessionID:           session.Spec.SessionID,
		Code:                payload.Code,
		State:               payload.State,
		ProviderRedirectURI: resolveExchangeProviderRedirectURI(payload, codeSession),
	})
}

func (e *SessionExecutor) PollDevice(ctx context.Context, session *platformv1alpha1.OAuthAuthorizationSessionResource) (*credentialcontract.DeviceAuthorizationResult, error) {
	if session == nil {
		return nil, fmt.Errorf("platformk8s/oauth: device poll session is nil")
	}
	authorizer, err := e.registry.DeviceFlowAuthorizer(credentialcontract.OAuthCLIID(session.Spec.CliID))
	if err != nil {
		return nil, err
	}
	return authorizer.PollAuthorizationSession(ctx, session.Spec.SessionID)
}

func (e *SessionExecutor) ImportCredential(ctx context.Context, session *platformv1alpha1.OAuthAuthorizationSessionResource, artifact *credentialcontract.OAuthArtifact) (*platformv1alpha1.ImportedCredentialSummary, error) {
	if session == nil {
		return nil, fmt.Errorf("platformk8s/oauth: import session is nil")
	}
	if artifact == nil {
		return nil, fmt.Errorf("platformk8s/oauth: import artifact is nil")
	}
	if err := e.sessionStore.PutArtifact(ctx, session.Spec.CliID, session.Spec.SessionID, artifact); err != nil {
		return nil, err
	}
	definition, err := e.importer.ImportOAuthCredential(ctx, &credentialcontract.OAuthImportRequest{
		CliID:        credentialcontract.OAuthCLIID(session.Spec.CliID),
		CredentialID: session.Spec.TargetCredentialID,
		DisplayName:  session.Spec.TargetDisplayName,
		Artifact:     *artifact,
	})
	if err != nil {
		return nil, err
	}
	return importedCredentialSummary(definition, session), nil
}

func resolveExchangeProviderRedirectURI(payload *OAuthCodeCallbackPayload, session *CodeOAuthSession) string {
	if session != nil {
		if providerRedirectURI := strings.TrimSpace(session.ProviderRedirectURI); providerRedirectURI != "" {
			return providerRedirectURI
		}
	}
	if payload == nil {
		return ""
	}
	return strings.TrimSpace(payload.ProviderRedirectURI)
}

func importedCredentialSummary(definition *credentialv1.CredentialDefinition, session *platformv1alpha1.OAuthAuthorizationSessionResource) *platformv1alpha1.ImportedCredentialSummary {
	summary := &platformv1alpha1.ImportedCredentialSummary{
		CredentialID: session.Spec.TargetCredentialID,
		DisplayName:  session.Spec.TargetDisplayName,
		Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH.String(),
	}
	if definition == nil {
		return summary
	}
	if credentialID := strings.TrimSpace(definition.GetCredentialId()); credentialID != "" {
		summary.CredentialID = credentialID
	}
	if displayName := strings.TrimSpace(definition.GetDisplayName()); displayName != "" {
		summary.DisplayName = displayName
	}
	if kind := definition.GetKind(); kind != credentialv1.CredentialKind_CREDENTIAL_KIND_UNSPECIFIED {
		summary.Kind = kind.String()
	}
	return summary
}
