// Package credential defines the platform-owned OAuth credential management
// contracts including authorization flows and credential import.
package credential

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// OAuthCLIID identifies one CLI-owned OAuth surface.
// Values are data-driven (registered at runtime) and should match cli_id.
type OAuthCLIID string

// OAuthAuthorizationSession describes one pending CLI OAuth authorization flow.
type OAuthAuthorizationSession struct {
	CliID            OAuthCLIID
	SessionID        string
	AuthorizationURL string
	ExpiresAt        time.Time
}

// OAuthAuthorizationRequest describes one request to start one CLI OAuth flow.
type OAuthAuthorizationRequest struct {
	CliID               OAuthCLIID
	ProviderRedirectURI string
}

// OAuthAuthorizationExchange describes one completed CLI OAuth callback result.
type OAuthAuthorizationExchange struct {
	CliID               OAuthCLIID
	SessionID           string
	Code                string
	State               string
	ProviderRedirectURI string
}

// OAuthArtifact describes one CLI-owned OAuth token bundle.
// CLI identity is determined by the calling context, not stored in the artifact.
type OAuthArtifact struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	// TokenResponseJSON stores the raw OAuth token response body when the
	// authorizer needs package-driven projection against token response fields.
	TokenResponseJSON string
	TokenType         string
	AccountID         string
	AccountEmail      string
	Scopes            []string
	ExpiresAt         *time.Time
}

// OAuthImportRequest describes one OAuth credential import operation.
// CliID should carry the cli_id that owns the OAuth path.
type OAuthImportRequest struct {
	CliID        OAuthCLIID
	CredentialID string
	DisplayName  string
	Artifact     OAuthArtifact
}

// OAuthAuthorizer starts and completes CLI-specific authorization flows.
type OAuthAuthorizer interface {
	// StartAuthorizationSession starts one CLI-specific authorization flow.
	StartAuthorizationSession(ctx context.Context, request *OAuthAuthorizationRequest) (*OAuthAuthorizationSession, error)

	// CompleteAuthorizationSession turns one callback result into an OAuth artifact.
	CompleteAuthorizationSession(ctx context.Context, exchange *OAuthAuthorizationExchange) (*OAuthArtifact, error)
}

// OAuthCredentialImporter imports CLI-owned OAuth artifacts into
// platform-owned credential storage.
type OAuthCredentialImporter interface {
	// ImportOAuthCredential stores one OAuth artifact as one platform-owned OAuth credential.
	ImportOAuthCredential(ctx context.Context, request *OAuthImportRequest) (*CredentialDefinition, error)
}

// ValidateOAuthArtifact validates one OAuth artifact.
func ValidateOAuthArtifact(artifact *OAuthArtifact) error {
	if artifact == nil {
		return fmt.Errorf("credential: oauth artifact is nil")
	}
	if strings.TrimSpace(artifact.AccessToken) == "" {
		return fmt.Errorf("credential: oauth access token is empty")
	}
	return nil
}

// ValidateOAuthAuthorizationSession validates one pending authorization session.
func ValidateOAuthAuthorizationSession(session *OAuthAuthorizationSession) error {
	if session == nil {
		return fmt.Errorf("credential: oauth authorization session is nil")
	}
	if strings.TrimSpace(string(session.CliID)) == "" {
		return fmt.Errorf("credential: oauth authorization session cli id is empty")
	}
	if strings.TrimSpace(session.SessionID) == "" {
		return fmt.Errorf("credential: oauth authorization session id is empty")
	}
	if strings.TrimSpace(session.AuthorizationURL) == "" {
		return fmt.Errorf("credential: oauth authorization url is empty")
	}
	if _, err := url.ParseRequestURI(strings.TrimSpace(session.AuthorizationURL)); err != nil {
		return fmt.Errorf("credential: oauth authorization url is invalid: %w", err)
	}
	if session.ExpiresAt.IsZero() {
		return fmt.Errorf("credential: oauth authorization session expiry is empty")
	}
	return nil
}

// ValidateOAuthAuthorizationRequest validates one authorization start request.
func ValidateOAuthAuthorizationRequest(request *OAuthAuthorizationRequest) error {
	if request == nil {
		return fmt.Errorf("credential: oauth authorization request is nil")
	}
	if strings.TrimSpace(string(request.CliID)) == "" {
		return fmt.Errorf("credential: oauth authorization request cli id is empty")
	}
	if strings.TrimSpace(request.ProviderRedirectURI) == "" {
		return fmt.Errorf("credential: oauth authorization provider redirect uri is empty")
	}
	if _, err := url.ParseRequestURI(strings.TrimSpace(request.ProviderRedirectURI)); err != nil {
		return fmt.Errorf("credential: oauth authorization provider redirect uri is invalid: %w", err)
	}
	return nil
}

// ValidateOAuthAuthorizationExchange validates one authorization callback result.
func ValidateOAuthAuthorizationExchange(exchange *OAuthAuthorizationExchange) error {
	if exchange == nil {
		return fmt.Errorf("credential: oauth authorization exchange is nil")
	}
	if strings.TrimSpace(string(exchange.CliID)) == "" {
		return fmt.Errorf("credential: oauth authorization exchange cli id is empty")
	}
	if strings.TrimSpace(exchange.SessionID) == "" {
		return fmt.Errorf("credential: oauth authorization exchange session id is empty")
	}
	if strings.TrimSpace(exchange.Code) == "" {
		return fmt.Errorf("credential: oauth authorization exchange code is empty")
	}
	if strings.TrimSpace(exchange.State) == "" {
		return fmt.Errorf("credential: oauth authorization exchange state is empty")
	}
	if strings.TrimSpace(exchange.ProviderRedirectURI) == "" {
		return fmt.Errorf("credential: oauth authorization exchange provider redirect uri is empty")
	}
	if _, err := url.ParseRequestURI(strings.TrimSpace(exchange.ProviderRedirectURI)); err != nil {
		return fmt.Errorf("credential: oauth authorization exchange provider redirect uri is invalid: %w", err)
	}
	return nil
}

// ValidateOAuthImportRequest validates one OAuth import request.
func ValidateOAuthImportRequest(request *OAuthImportRequest) error {
	if request == nil {
		return fmt.Errorf("credential: oauth import request is nil")
	}
	if strings.TrimSpace(string(request.CliID)) == "" {
		return fmt.Errorf("credential: oauth import cli id is empty")
	}
	if strings.TrimSpace(request.CredentialID) == "" {
		return fmt.Errorf("credential: oauth import credential id is empty")
	}
	if strings.TrimSpace(request.DisplayName) == "" {
		return fmt.Errorf("credential: oauth import display name is empty")
	}
	return ValidateOAuthArtifact(&request.Artifact)
}
