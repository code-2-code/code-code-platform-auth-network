package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type OAuthCodeCallbackPayload struct {
	Code                string
	State               string
	ProviderRedirectURI string
	Error               string
	ErrorDescription    string
	ReceivedAt          time.Time
}

func (s *OAuthSessionSecretStore) FindCodeSessionByState(ctx context.Context, cliID, state string) (*CodeOAuthSession, error) {
	trimmedCLIID := strings.TrimSpace(cliID)
	if trimmedCLIID == "" {
		return nil, fmt.Errorf("platformk8s: oauth code session cli id is empty")
	}
	trimmedState := strings.TrimSpace(state)
	if trimmedState == "" {
		return nil, fmt.Errorf("platformk8s: oauth code session callback state is empty")
	}
	if err := s.ensureReady(); err != nil {
		return nil, err
	}
	list := &corev1.SecretList{}
	if err := s.reader.List(
		ctx,
		list,
		ctrlclient.InNamespace(s.namespace),
		ctrlclient.MatchingLabels{
			oauthSessionManagedLabel: "true",
			oauthSessionCLILabel:     trimmedCLIID,
		},
	); err != nil {
		return nil, fmt.Errorf("platformk8s: list oauth code sessions for %q: %w", trimmedCLIID, err)
	}
	for i := range list.Items {
		record, err := codeOAuthSessionFromSecret(&list.Items[i])
		if err != nil {
			continue
		}
		if record.State == trimmedState {
			return record, nil
		}
	}
	return nil, fmt.Errorf("platformk8s: oauth code session for %q callback state not found", trimmedCLIID)
}

func (s *OAuthSessionSecretStore) PutCodeCallback(ctx context.Context, cliID, sessionID string, payload *OAuthCodeCallbackPayload) error {
	if payload == nil {
		return fmt.Errorf("platformk8s: oauth callback payload is nil")
	}
	return s.updateSessionSecret(ctx, cliID, sessionID, func(data map[string][]byte) error {
		data[oauthCallbackCodeKey] = []byte(strings.TrimSpace(payload.Code))
		data[oauthCallbackStateKey] = []byte(strings.TrimSpace(payload.State))
		data[oauthCodeSessionProviderRedirectURIKey] = []byte(strings.TrimSpace(payload.ProviderRedirectURI))
		data[oauthCallbackErrorKey] = []byte(strings.TrimSpace(payload.Error))
		data[oauthCallbackErrorDetailKey] = []byte(strings.TrimSpace(payload.ErrorDescription))
		data[oauthCallbackReceivedAtKey] = []byte(payload.ReceivedAt.UTC().Format(time.RFC3339))
		return nil
	})
}

func (s *OAuthSessionSecretStore) GetCodeCallback(ctx context.Context, cliID, sessionID string) (*OAuthCodeCallbackPayload, error) {
	secret, err := s.getSessionSecret(ctx, cliID, sessionID)
	if err != nil {
		return nil, err
	}
	return callbackPayloadFromSecret(secret)
}

func callbackPayloadFromSecret(secret *corev1.Secret) (*OAuthCodeCallbackPayload, error) {
	if secret == nil {
		return nil, fmt.Errorf("platformk8s: oauth callback secret is nil")
	}
	receivedAtText := strings.TrimSpace(string(secret.Data[oauthCallbackReceivedAtKey]))
	if receivedAtText == "" {
		return nil, fmt.Errorf("platformk8s: oauth callback not recorded")
	}
	receivedAt, err := time.Parse(time.RFC3339, receivedAtText)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: parse oauth callback time: %w", err)
	}
	return &OAuthCodeCallbackPayload{
		Code:                strings.TrimSpace(string(secret.Data[oauthCallbackCodeKey])),
		State:               strings.TrimSpace(string(secret.Data[oauthCallbackStateKey])),
		ProviderRedirectURI: strings.TrimSpace(string(secret.Data[oauthCodeSessionProviderRedirectURIKey])),
		Error:               strings.TrimSpace(string(secret.Data[oauthCallbackErrorKey])),
		ErrorDescription:    strings.TrimSpace(string(secret.Data[oauthCallbackErrorDetailKey])),
		ReceivedAt:          receivedAt.UTC(),
	}, nil
}
