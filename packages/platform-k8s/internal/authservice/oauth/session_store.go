package oauth

import (
	"fmt"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
)

const (
	oauthSessionManagedLabel    = "credential.code-code.internal/oauth-session"
	oauthSessionCLILabel        = "credential.code-code.internal/oauth-cli"
	oauthSessionIDKey           = "session_id"
	oauthSessionExpiresAtKey    = "expires_at"
	oauthCallbackCodeKey        = "callback_code"
	oauthCallbackErrorKey       = "callback_error"
	oauthCallbackErrorDetailKey = "callback_error_description"
	oauthCallbackStateKey       = "callback_state"
	oauthCallbackReceivedAtKey  = "callback_received_at"
	oauthAccessTokenKey         = "access_token"
	oauthRefreshTokenKey        = "refresh_token"
	oauthIDTokenKey             = "id_token"
	oauthTokenResponseJSONKey   = "token_response_json"
	oauthTokenTypeKey           = "token_type"
	oauthAccountIDKey           = "account_id"
	oauthAccountEmailKey        = "account_email"
	oauthScopesKey              = "scopes"

	oauthSessionSecretPrefix               = "oauth-session-"
	oauthCodeSessionProviderRedirectURIKey = "provider_redirect_uri"
	oauthCodeSessionStateKey               = "state"
	oauthCodeSessionCodeVerifierKey        = "code_verifier"
	oauthDeviceSessionDeviceCodeKey        = "device_code"
	oauthDeviceSessionCodeVerifierKey      = "code_verifier"
	oauthDeviceSessionPollIntervalKey      = "poll_interval_seconds"
)

type OAuthSessionSecretStore struct {
	client    ctrlclient.Client
	reader    ctrlclient.Reader
	namespace string
}

type OAuthSessionStore = OAuthSessionSecretStore

func NewOAuthSessionStore(client ctrlclient.Client, reader ctrlclient.Reader, namespace string) (*OAuthSessionSecretStore, error) {
	if client == nil {
		return nil, fmt.Errorf("platformk8s: client is nil")
	}
	if reader == nil {
		return nil, fmt.Errorf("platformk8s: reader is nil")
	}
	if strings.TrimSpace(namespace) == "" {
		return nil, fmt.Errorf("platformk8s: namespace is empty")
	}
	return &OAuthSessionSecretStore{
		client:    client,
		reader:    reader,
		namespace: strings.TrimSpace(namespace),
	}, nil
}
