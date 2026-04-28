package oauth

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

type CodeOAuthSession struct {
	CliID               string
	SessionID           string
	ProviderRedirectURI string
	State               string
	CodeVerifier        string
	Issuer              string
	Nonce               string
	ExpiresAt           time.Time
}

type DeviceOAuthSession struct {
	CliID               string
	SessionID           string
	DeviceCode          string
	CodeVerifier        string
	PollIntervalSeconds int32
	ExpiresAt           time.Time
}

func (s *OAuthSessionSecretStore) PutCodeSession(ctx context.Context, session *CodeOAuthSession) error {
	if err := validateCodeOAuthSession(session); err != nil {
		return err
	}
	return s.putSession(ctx, session.CliID, session.SessionID, map[string][]byte{
		oauthCLIIDSecretKey:                    []byte(strings.TrimSpace(session.CliID)),
		oauthSessionIDKey:                      []byte(strings.TrimSpace(session.SessionID)),
		oauthCodeSessionProviderRedirectURIKey: []byte(strings.TrimSpace(session.ProviderRedirectURI)),
		oauthCodeSessionStateKey:               []byte(strings.TrimSpace(session.State)),
		oauthCodeSessionCodeVerifierKey:        []byte(strings.TrimSpace(session.CodeVerifier)),
		oauthSessionExpiresAtKey:               []byte(session.ExpiresAt.UTC().Format(time.RFC3339)),
	})
}

func (s *OAuthSessionSecretStore) GetCodeSession(ctx context.Context, cliID, sessionID string) (*CodeOAuthSession, error) {
	secret, err := s.getSessionSecret(ctx, cliID, sessionID)
	if err != nil {
		return nil, err
	}
	return codeOAuthSessionFromSecret(secret)
}

func (s *OAuthSessionSecretStore) DeleteCodeSession(ctx context.Context, cliID, sessionID string) error {
	return s.deleteSession(ctx, cliID, sessionID)
}

func (s *OAuthSessionSecretStore) PutDeviceSession(ctx context.Context, session *DeviceOAuthSession) error {
	if err := validateDeviceOAuthSession(session); err != nil {
		return err
	}
	return s.putSession(ctx, session.CliID, session.SessionID, map[string][]byte{
		oauthCLIIDSecretKey:               []byte(strings.TrimSpace(session.CliID)),
		oauthSessionIDKey:                 []byte(strings.TrimSpace(session.SessionID)),
		oauthDeviceSessionDeviceCodeKey:   []byte(strings.TrimSpace(session.DeviceCode)),
		oauthDeviceSessionCodeVerifierKey: []byte(strings.TrimSpace(session.CodeVerifier)),
		oauthDeviceSessionPollIntervalKey: []byte(fmt.Sprintf("%d", session.PollIntervalSeconds)),
		oauthSessionExpiresAtKey:          []byte(session.ExpiresAt.UTC().Format(time.RFC3339)),
	})
}

func (s *OAuthSessionSecretStore) GetDeviceSession(ctx context.Context, cliID, sessionID string) (*DeviceOAuthSession, error) {
	secret, err := s.getSessionSecret(ctx, cliID, sessionID)
	if err != nil {
		return nil, err
	}
	return deviceOAuthSessionFromSecret(secret)
}

func (s *OAuthSessionSecretStore) DeleteDeviceSession(ctx context.Context, cliID, sessionID string) error {
	return s.deleteSession(ctx, cliID, sessionID)
}

func codeOAuthSessionFromSecret(secret *corev1.Secret) (*CodeOAuthSession, error) {
	if secret == nil {
		return nil, fmt.Errorf("platformk8s: oauth code session secret is nil")
	}
	expiresAt, ok := sessionSecretExpiresAt(secret)
	if !ok {
		return nil, fmt.Errorf("platformk8s: oauth code session %q expiry is empty", secret.Name)
	}
	session := &CodeOAuthSession{
		CliID:               strings.TrimSpace(string(secret.Data[oauthCLIIDSecretKey])),
		SessionID:           strings.TrimSpace(string(secret.Data[oauthSessionIDKey])),
		ProviderRedirectURI: strings.TrimSpace(string(secret.Data[oauthCodeSessionProviderRedirectURIKey])),
		State:               strings.TrimSpace(string(secret.Data[oauthCodeSessionStateKey])),
		CodeVerifier:        strings.TrimSpace(string(secret.Data[oauthCodeSessionCodeVerifierKey])),
		ExpiresAt:           expiresAt,
	}
	if err := validateCodeOAuthSession(session); err != nil {
		return nil, err
	}
	return session, nil
}

func deviceOAuthSessionFromSecret(secret *corev1.Secret) (*DeviceOAuthSession, error) {
	if secret == nil {
		return nil, fmt.Errorf("platformk8s: oauth device session secret is nil")
	}
	expiresAt, ok := sessionSecretExpiresAt(secret)
	if !ok {
		return nil, fmt.Errorf("platformk8s: oauth device session %q expiry is empty", secret.Name)
	}
	pollInterval, err := parsePositiveInt32(string(secret.Data[oauthDeviceSessionPollIntervalKey]))
	if err != nil {
		return nil, fmt.Errorf("platformk8s: parse oauth device session %q poll interval: %w", secret.Name, err)
	}
	session := &DeviceOAuthSession{
		CliID:               strings.TrimSpace(string(secret.Data[oauthCLIIDSecretKey])),
		SessionID:           strings.TrimSpace(string(secret.Data[oauthSessionIDKey])),
		DeviceCode:          strings.TrimSpace(string(secret.Data[oauthDeviceSessionDeviceCodeKey])),
		CodeVerifier:        strings.TrimSpace(string(secret.Data[oauthDeviceSessionCodeVerifierKey])),
		PollIntervalSeconds: pollInterval,
		ExpiresAt:           expiresAt,
	}
	if err := validateDeviceOAuthSession(session); err != nil {
		return nil, err
	}
	return session, nil
}

func validateCodeOAuthSession(session *CodeOAuthSession) error {
	if session == nil {
		return fmt.Errorf("platformk8s: oauth code session is nil")
	}
	if strings.TrimSpace(session.CliID) == "" {
		return fmt.Errorf("platformk8s: oauth code session cli id is empty")
	}
	if strings.TrimSpace(session.SessionID) == "" {
		return fmt.Errorf("platformk8s: oauth code session id is empty")
	}
	if strings.TrimSpace(session.ProviderRedirectURI) == "" {
		return fmt.Errorf("platformk8s: oauth code session provider redirect uri is empty")
	}
	if _, err := url.ParseRequestURI(strings.TrimSpace(session.ProviderRedirectURI)); err != nil {
		return fmt.Errorf("platformk8s: oauth code session provider redirect uri is invalid: %w", err)
	}
	if strings.TrimSpace(session.State) == "" {
		return fmt.Errorf("platformk8s: oauth code session state is empty")
	}
	if strings.TrimSpace(session.CodeVerifier) == "" {
		return fmt.Errorf("platformk8s: oauth code session code verifier is empty")
	}
	if session.ExpiresAt.IsZero() {
		return fmt.Errorf("platformk8s: oauth code session expiry is empty")
	}
	return nil
}

func validateDeviceOAuthSession(session *DeviceOAuthSession) error {
	if session == nil {
		return fmt.Errorf("platformk8s: oauth device session is nil")
	}
	if strings.TrimSpace(session.CliID) == "" {
		return fmt.Errorf("platformk8s: oauth device session cli id is empty")
	}
	if strings.TrimSpace(session.SessionID) == "" {
		return fmt.Errorf("platformk8s: oauth device session id is empty")
	}
	if strings.TrimSpace(session.DeviceCode) == "" {
		return fmt.Errorf("platformk8s: oauth device session device code is empty")
	}
	if strings.TrimSpace(session.CodeVerifier) == "" {
		return fmt.Errorf("platformk8s: oauth device session code verifier is empty")
	}
	if session.PollIntervalSeconds <= 0 {
		return fmt.Errorf("platformk8s: oauth device session poll interval is empty")
	}
	if session.ExpiresAt.IsZero() {
		return fmt.Errorf("platformk8s: oauth device session expiry is empty")
	}
	return nil
}
