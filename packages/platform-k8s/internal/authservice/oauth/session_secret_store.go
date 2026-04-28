package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"code-code.internal/platform-k8s/internal/platform/resourceops"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (s *OAuthSessionSecretStore) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	if err := s.ensureReady(); err != nil {
		return err
	}
	list := &corev1.SecretList{}
	if err := s.client.List(
		ctx,
		list,
		ctrlclient.InNamespace(s.namespace),
		ctrlclient.MatchingLabels{oauthSessionManagedLabel: "true"},
	); err != nil {
		return fmt.Errorf("platformk8s: list oauth sessions: %w", err)
	}
	for i := range list.Items {
		expiresAt, ok := sessionSecretExpiresAt(&list.Items[i])
		if !ok || now.UTC().Before(expiresAt) {
			continue
		}
		if err := s.client.Delete(ctx, &list.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("platformk8s: delete expired oauth session %q: %w", list.Items[i].Name, err)
		}
	}
	return nil
}

func (s *OAuthSessionSecretStore) putSession(ctx context.Context, cliID, sessionID string, data map[string][]byte) error {
	trimmedCLIID, trimmedSessionID, err := normalizeSessionKey(cliID, sessionID)
	if err != nil {
		return err
	}
	if err := s.ensureReady(); err != nil {
		return err
	}
	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oauthSessionSecretName(trimmedCLIID, trimmedSessionID),
			Namespace: s.namespace,
			Labels: map[string]string{
				oauthSessionManagedLabel: "true",
				oauthSessionCLILabel:     trimmedCLIID,
			},
		},
		Data: data,
	}
	return resourceops.UpsertResource(ctx, s.client, secret, s.namespace, secret.Name)
}

func (s *OAuthSessionSecretStore) getSessionSecret(ctx context.Context, cliID, sessionID string) (*corev1.Secret, error) {
	key, err := s.sessionSecretObjectKey(cliID, sessionID)
	if err != nil {
		return nil, err
	}
	trimmedCLIID := strings.TrimSpace(cliID)
	trimmedSessionID := strings.TrimSpace(sessionID)
	secret := &corev1.Secret{}
	if err := s.reader.Get(ctx, key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("platformk8s: oauth session %q for %q not found", trimmedSessionID, trimmedCLIID)
		}
		return nil, fmt.Errorf("platformk8s: get oauth session %q for %q: %w", trimmedSessionID, trimmedCLIID, err)
	}
	return secret, nil
}

func (s *OAuthSessionSecretStore) deleteSession(ctx context.Context, cliID, sessionID string) error {
	key, err := s.sessionSecretObjectKey(cliID, sessionID)
	if err != nil {
		return err
	}
	trimmedCLIID := strings.TrimSpace(cliID)
	trimmedSessionID := strings.TrimSpace(sessionID)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}}
	if err := s.client.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("platformk8s: delete oauth session %q for %q: %w", trimmedSessionID, trimmedCLIID, err)
	}
	return nil
}

func (s *OAuthSessionSecretStore) updateSessionSecret(
	ctx context.Context,
	cliID, sessionID string,
	mutate func(data map[string][]byte) error,
) error {
	key, err := s.sessionSecretObjectKey(cliID, sessionID)
	if err != nil {
		return err
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &corev1.Secret{}
		if err := s.reader.Get(ctx, key, current); err != nil {
			return err
		}
		if current.Data == nil {
			current.Data = map[string][]byte{}
		}
		if err := mutate(current.Data); err != nil {
			return err
		}
		return s.client.Update(ctx, current)
	}); err != nil {
		return fmt.Errorf("platformk8s: update %q: %w", key.String(), err)
	}
	return nil
}

func (s *OAuthSessionSecretStore) sessionSecretObjectKey(cliID, sessionID string) (ctrlclient.ObjectKey, error) {
	trimmedCLIID, trimmedSessionID, err := normalizeSessionKey(cliID, sessionID)
	if err != nil {
		return ctrlclient.ObjectKey{}, err
	}
	if err := s.ensureReady(); err != nil {
		return ctrlclient.ObjectKey{}, err
	}
	return ctrlclient.ObjectKey{
		Namespace: s.namespace,
		Name:      oauthSessionSecretName(trimmedCLIID, trimmedSessionID),
	}, nil
}

func (s *OAuthSessionSecretStore) ensureReady() error {
	if s == nil || s.client == nil || s.reader == nil {
		return fmt.Errorf("platformk8s: oauth session store is not initialized")
	}
	return nil
}

func normalizeSessionKey(cliID, sessionID string) (string, string, error) {
	trimmedCLIID := strings.TrimSpace(cliID)
	if trimmedCLIID == "" {
		return "", "", fmt.Errorf("platformk8s: oauth session cli id is empty")
	}
	trimmedSessionID := strings.TrimSpace(sessionID)
	if trimmedSessionID == "" {
		return "", "", fmt.Errorf("platformk8s: oauth session id is empty")
	}
	return trimmedCLIID, trimmedSessionID, nil
}

func oauthSessionSecretName(cliID, sessionID string) string {
	return oauthSessionSecretPrefix + strings.ToLower(strings.TrimSpace(cliID)) + "-" + strings.ToLower(strings.TrimSpace(sessionID))
}

func sessionSecretExpiresAt(secret *corev1.Secret) (time.Time, bool) {
	if secret == nil {
		return time.Time{}, false
	}
	expiresAtText := strings.TrimSpace(string(secret.Data[oauthSessionExpiresAtKey]))
	if expiresAtText == "" {
		return time.Time{}, false
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresAtText)
	if err != nil {
		return time.Time{}, false
	}
	return expiresAt.UTC(), true
}
