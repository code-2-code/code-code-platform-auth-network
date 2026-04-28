package credentials

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"code-code.internal/platform-k8s/internal/platform/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRefreshRunnerRefreshesOAuthCredentialAndWritesStatus(t *testing.T) {
	ctx := context.Background()
	expiresSoon := time.Now().UTC().Add(time.Minute)
	nextExpiry := time.Now().UTC().Add(time.Hour)
	credential := &platformv1alpha1.CredentialDefinitionResource{
		TypeMeta: metav1.TypeMeta{APIVersion: platformv1alpha1.GroupVersion.String(), Kind: platformv1alpha1.KindCredentialDefinitionResource},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "credential-codex",
			Namespace:  "code-code",
			Generation: 3,
		},
		Spec: platformv1alpha1.CredentialDefinitionResourceSpec{
			Definition: &credentialv1.CredentialDefinition{
				CredentialId: "credential-codex",
				DisplayName:  "Codex",
				Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
				KindMetadata: &credentialv1.CredentialDefinition_OauthMetadata{
					OauthMetadata: &credentialv1.OAuthMetadata{
						CliId: "codex",
					},
				},
			},
		},
		Status: platformv1alpha1.CredentialDefinitionResourceStatus{
			OAuth: &platformv1alpha1.CredentialOAuthStatus{CredentialGeneration: 1},
		},
	}
	materialStore := newMemoryCredentialMaterialStore(map[string]map[string]string{
		"credential-codex": newRefreshTestMaterial(expiresSoon),
	})
	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(credential).
		WithStatusSubresource(&platformv1alpha1.CredentialDefinitionResource{}).
		Build()
	runner, err := NewRefreshRunner(RefreshRunnerConfig{
		Client:    client,
		Namespace: "code-code",
		Material:  materialStore,
		Refreshers: []OAuthTokenRefresher{staticRefresher{
			cliID: "codex",
			result: &OAuthRefreshResult{
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
				TokenType:    "Bearer",
				ExpiresAt:    &nextExpiry,
				AccountEmail: "new@example.test",
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewRefreshRunner() error = %v", err)
	}

	if err := runner.RunAll(ctx); err != nil {
		t.Fatalf("RunAll() error = %v", err)
	}

	values := materialStore.valuesForTest("credential-codex")
	if got := values[materialKeyAccessToken]; got != "new-access" {
		t.Fatalf("access token = %q, want new-access", got)
	}
	updatedCredential := &platformv1alpha1.CredentialDefinitionResource{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: "code-code", Name: "credential-codex"}, updatedCredential); err != nil {
		t.Fatalf("get credential: %v", err)
	}
	if updatedCredential.Status.ObservedGeneration != 3 {
		t.Fatalf("observed generation = %d, want 3", updatedCredential.Status.ObservedGeneration)
	}
	if updatedCredential.Status.OAuth == nil || updatedCredential.Status.OAuth.CredentialGeneration != 2 {
		t.Fatalf("unexpected oauth status: %+v", updatedCredential.Status.OAuth)
	}
}

type staticRefresher struct {
	cliID       string
	result      *OAuthRefreshResult
	err         error
	refreshLead time.Duration
}

func (r staticRefresher) CliID() string {
	if r.cliID != "" {
		return r.cliID
	}
	return "codex"
}

func (r staticRefresher) Refresh(_ context.Context, _ *http.Client, _ string) (*OAuthRefreshResult, error) {
	return r.result, r.err
}

func (r staticRefresher) RefreshLead() time.Duration {
	if r.refreshLead > 0 {
		return r.refreshLead
	}
	return 5 * time.Minute
}

func (staticRefresher) IsNonRetryable(err error) bool { return errors.Is(err, errNonRetryableTest) }

var errNonRetryableTest = errors.New("non-retryable")

func TestRefreshRunnerMatchesRefresherByCLIID(t *testing.T) {
	ctx := context.Background()
	expiresSoon := time.Now().UTC().Add(time.Minute)
	nextExpiry := time.Now().UTC().Add(time.Hour)
	credential := &platformv1alpha1.CredentialDefinitionResource{
		TypeMeta: metav1.TypeMeta{APIVersion: platformv1alpha1.GroupVersion.String(), Kind: platformv1alpha1.KindCredentialDefinitionResource},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "credential-gemini-cli",
			Namespace:  "code-code",
			Generation: 1,
		},
		Spec: platformv1alpha1.CredentialDefinitionResourceSpec{
			Definition: &credentialv1.CredentialDefinition{
				CredentialId: "credential-gemini-cli",
				DisplayName:  "Gemini CLI",
				Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
				KindMetadata: &credentialv1.CredentialDefinition_OauthMetadata{
					OauthMetadata: &credentialv1.OAuthMetadata{
						CliId: "gemini-cli",
					},
				},
			},
		},
	}
	materialStore := newMemoryCredentialMaterialStore(map[string]map[string]string{
		"credential-gemini-cli": newRefreshTestMaterial(expiresSoon),
	})
	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(credential).
		WithStatusSubresource(&platformv1alpha1.CredentialDefinitionResource{}).
		Build()
	runner, err := NewRefreshRunner(RefreshRunnerConfig{
		Client:    client,
		Namespace: "code-code",
		Material:  materialStore,
		Refreshers: []OAuthTokenRefresher{staticRefresher{
			cliID: "gemini-cli",
			result: &OAuthRefreshResult{
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
				TokenType:    "Bearer",
				ExpiresAt:    &nextExpiry,
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewRefreshRunner() error = %v", err)
	}

	if err := runner.RunAll(ctx); err != nil {
		t.Fatalf("RunAll() error = %v", err)
	}

	values := materialStore.valuesForTest("credential-gemini-cli")
	if got := values[materialKeyAccessToken]; got != "new-access" {
		t.Fatalf("access token = %q, want new-access", got)
	}
}

func TestRefreshRunnerEnsureFreshRespectsMinTTL(t *testing.T) {
	ctx := context.Background()
	expiresSoon := time.Now().UTC().Add(20 * time.Minute)
	nextExpiry := time.Now().UTC().Add(2 * time.Hour)
	credential := &platformv1alpha1.CredentialDefinitionResource{
		TypeMeta: metav1.TypeMeta{APIVersion: platformv1alpha1.GroupVersion.String(), Kind: platformv1alpha1.KindCredentialDefinitionResource},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "credential-codex",
			Namespace:  "code-code",
			Generation: 1,
		},
		Spec: platformv1alpha1.CredentialDefinitionResourceSpec{
			Definition: &credentialv1.CredentialDefinition{
				CredentialId: "credential-codex",
				Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
				KindMetadata: &credentialv1.CredentialDefinition_OauthMetadata{
					OauthMetadata: &credentialv1.OAuthMetadata{CliId: "codex"},
				},
			},
		},
		Status: platformv1alpha1.CredentialDefinitionResourceStatus{
			OAuth: &platformv1alpha1.CredentialOAuthStatus{CredentialGeneration: 1},
		},
	}
	materialStore := newMemoryCredentialMaterialStore(map[string]map[string]string{
		"credential-codex": newRefreshTestMaterial(expiresSoon),
	})
	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(credential).
		WithStatusSubresource(&platformv1alpha1.CredentialDefinitionResource{}).
		Build()
	runner, err := NewRefreshRunner(RefreshRunnerConfig{
		Client:    client,
		Namespace: "code-code",
		Material:  materialStore,
		Refreshers: []OAuthTokenRefresher{staticRefresher{
			cliID: "codex",
			result: &OAuthRefreshResult{
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
				ExpiresAt:    &nextExpiry,
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewRefreshRunner() error = %v", err)
	}

	result, err := runner.EnsureFresh(ctx, "credential-codex", EnsureFreshOptions{
		MinTTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("EnsureFresh() error = %v", err)
	}
	if result == nil || !result.Refreshed {
		t.Fatalf("EnsureFresh() refreshed = %v, want true", result)
	}

	values := materialStore.valuesForTest("credential-codex")
	if got, want := values[materialKeyAccessToken], "new-access"; got != want {
		t.Fatalf("access token = %q, want %q", got, want)
	}
}

func TestRefreshRunnerEnsureFreshDoesNotUseScheduledWindow(t *testing.T) {
	ctx := context.Background()
	expiresLater := time.Now().UTC().Add(2 * time.Hour)
	credential := &platformv1alpha1.CredentialDefinitionResource{
		TypeMeta: metav1.TypeMeta{APIVersion: platformv1alpha1.GroupVersion.String(), Kind: platformv1alpha1.KindCredentialDefinitionResource},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "credential-codex",
			Namespace:  "code-code",
			Generation: 1,
		},
		Spec: platformv1alpha1.CredentialDefinitionResourceSpec{
			Definition: &credentialv1.CredentialDefinition{
				CredentialId: "credential-codex",
				Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
				KindMetadata: &credentialv1.CredentialDefinition_OauthMetadata{
					OauthMetadata: &credentialv1.OAuthMetadata{CliId: "codex"},
				},
			},
		},
		Status: platformv1alpha1.CredentialDefinitionResourceStatus{
			OAuth: &platformv1alpha1.CredentialOAuthStatus{
				CredentialGeneration: 1,
				LastRefreshedAt:      &metav1.Time{Time: time.Now().UTC().Add(-time.Hour)},
			},
		},
	}
	materialStore := newMemoryCredentialMaterialStore(map[string]map[string]string{
		"credential-codex": newRefreshTestMaterial(expiresLater),
	})
	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(credential).
		WithStatusSubresource(&platformv1alpha1.CredentialDefinitionResource{}).
		Build()
	runner, err := NewRefreshRunner(RefreshRunnerConfig{
		Client:    client,
		Namespace: "code-code",
		Material:  materialStore,
		Refreshers: []OAuthTokenRefresher{staticRefresher{
			cliID: "codex",
			result: &OAuthRefreshResult{
				AccessToken: "new-access",
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewRefreshRunner() error = %v", err)
	}

	result, err := runner.EnsureFresh(ctx, "credential-codex", EnsureFreshOptions{
		MinTTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("EnsureFresh() error = %v", err)
	}
	if result == nil || result.Refreshed {
		t.Fatalf("EnsureFresh() refreshed = %v, want false", result)
	}

	values := materialStore.valuesForTest("credential-codex")
	if got, want := values[materialKeyAccessToken], "old-access"; got != want {
		t.Fatalf("access token = %q, want %q", got, want)
	}
}

func TestRefreshRunnerEnsureFreshForceRefreshOverridesExpiry(t *testing.T) {
	ctx := context.Background()
	expiresLater := time.Now().UTC().Add(2 * time.Hour)
	nextExpiry := time.Now().UTC().Add(4 * time.Hour)
	credential := &platformv1alpha1.CredentialDefinitionResource{
		TypeMeta: metav1.TypeMeta{APIVersion: platformv1alpha1.GroupVersion.String(), Kind: platformv1alpha1.KindCredentialDefinitionResource},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "credential-codex",
			Namespace:  "code-code",
			Generation: 1,
		},
		Spec: platformv1alpha1.CredentialDefinitionResourceSpec{
			Definition: &credentialv1.CredentialDefinition{
				CredentialId: "credential-codex",
				Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
				KindMetadata: &credentialv1.CredentialDefinition_OauthMetadata{
					OauthMetadata: &credentialv1.OAuthMetadata{CliId: "codex"},
				},
			},
		},
		Status: platformv1alpha1.CredentialDefinitionResourceStatus{
			OAuth: &platformv1alpha1.CredentialOAuthStatus{
				CredentialGeneration: 1,
				LastRefreshedAt:      &metav1.Time{Time: time.Now().UTC().Add(-time.Hour)},
			},
		},
	}
	materialStore := newMemoryCredentialMaterialStore(map[string]map[string]string{
		"credential-codex": newRefreshTestMaterial(expiresLater),
	})
	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(credential).
		WithStatusSubresource(&platformv1alpha1.CredentialDefinitionResource{}).
		Build()
	runner, err := NewRefreshRunner(RefreshRunnerConfig{
		Client:    client,
		Namespace: "code-code",
		Material:  materialStore,
		Refreshers: []OAuthTokenRefresher{staticRefresher{
			cliID: "codex",
			result: &OAuthRefreshResult{
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
				ExpiresAt:    &nextExpiry,
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewRefreshRunner() error = %v", err)
	}

	result, err := runner.EnsureFresh(ctx, "credential-codex", EnsureFreshOptions{
		MinTTL:       10 * time.Minute,
		ForceRefresh: true,
	})
	if err != nil {
		t.Fatalf("EnsureFresh() error = %v", err)
	}
	if result == nil || !result.Refreshed {
		t.Fatalf("EnsureFresh() refreshed = %v, want true", result)
	}

	values := materialStore.valuesForTest("credential-codex")
	if got, want := values[materialKeyAccessToken], "new-access"; got != want {
		t.Fatalf("access token = %q, want %q", got, want)
	}
}

func TestRefreshRunnerRunScheduledCredentialSkipsWhenTokenIsNotNearExpiry(t *testing.T) {
	ctx := context.Background()
	expiresLater := time.Now().UTC().Add(2 * time.Hour)
	nextExpiry := time.Now().UTC().Add(4 * time.Hour)
	credential := &platformv1alpha1.CredentialDefinitionResource{
		TypeMeta: metav1.TypeMeta{APIVersion: platformv1alpha1.GroupVersion.String(), Kind: platformv1alpha1.KindCredentialDefinitionResource},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "credential-codex",
			Namespace:  "code-code",
			Generation: 1,
		},
		Spec: platformv1alpha1.CredentialDefinitionResourceSpec{
			Definition: &credentialv1.CredentialDefinition{
				CredentialId: "credential-codex",
				Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
				KindMetadata: &credentialv1.CredentialDefinition_OauthMetadata{
					OauthMetadata: &credentialv1.OAuthMetadata{CliId: "codex"},
				},
			},
		},
		Status: platformv1alpha1.CredentialDefinitionResourceStatus{
			OAuth: &platformv1alpha1.CredentialOAuthStatus{
				CredentialGeneration: 1,
				LastRefreshedAt:      &metav1.Time{Time: time.Now().UTC().Add(-time.Hour)},
			},
		},
	}
	materialStore := newMemoryCredentialMaterialStore(map[string]map[string]string{
		"credential-codex": newRefreshTestMaterial(expiresLater),
	})
	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(credential).
		WithStatusSubresource(&platformv1alpha1.CredentialDefinitionResource{}).
		Build()
	runner, err := NewRefreshRunner(RefreshRunnerConfig{
		Client:    client,
		Namespace: "code-code",
		Material:  materialStore,
		Refreshers: []OAuthTokenRefresher{staticRefresher{
			cliID: "codex",
			result: &OAuthRefreshResult{
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
				ExpiresAt:    &nextExpiry,
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewRefreshRunner() error = %v", err)
	}

	result, err := runner.runScheduledCredential(ctx, "credential-codex")
	if err != nil {
		t.Fatalf("runScheduledCredential() error = %v", err)
	}
	if result == nil || result.Refreshed {
		t.Fatalf("runScheduledCredential() refreshed = %v, want false", result)
	}
}

func TestRefreshRunnerRunAllSkipsLongLivedTokensWithoutUsage(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	expiresLater := now.Add(72 * time.Hour)
	nextExpiry := now.Add(96 * time.Hour)
	credential := &platformv1alpha1.CredentialDefinitionResource{
		TypeMeta: metav1.TypeMeta{APIVersion: platformv1alpha1.GroupVersion.String(), Kind: platformv1alpha1.KindCredentialDefinitionResource},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "credential-codex",
			Namespace:  "code-code",
			Generation: 1,
		},
		Spec: platformv1alpha1.CredentialDefinitionResourceSpec{
			Definition: &credentialv1.CredentialDefinition{
				CredentialId: "credential-codex",
				Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH,
				KindMetadata: &credentialv1.CredentialDefinition_OauthMetadata{
					OauthMetadata: &credentialv1.OAuthMetadata{CliId: "codex"},
				},
			},
		},
		Status: platformv1alpha1.CredentialDefinitionResourceStatus{
			OAuth: &platformv1alpha1.CredentialOAuthStatus{
				CredentialGeneration: 1,
				LastRefreshedAt:      &metav1.Time{Time: now.Add(-25 * time.Hour)},
			},
		},
	}
	materialStore := newMemoryCredentialMaterialStore(map[string]map[string]string{
		"credential-codex": newRefreshTestMaterial(expiresLater),
	})
	client := ctrlclientfake.NewClientBuilder().
		WithScheme(testutil.NewScheme()).
		WithObjects(credential).
		WithStatusSubresource(&platformv1alpha1.CredentialDefinitionResource{}).
		Build()
	runner, err := NewRefreshRunner(RefreshRunnerConfig{
		Client:    client,
		Namespace: "code-code",
		Material:  materialStore,
		Refreshers: []OAuthTokenRefresher{staticRefresher{
			cliID: "codex",
			result: &OAuthRefreshResult{
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
				ExpiresAt:    &nextExpiry,
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewRefreshRunner() error = %v", err)
	}

	if err := runner.RunAll(ctx); err != nil {
		t.Fatalf("RunAll() error = %v", err)
	}

	values := materialStore.valuesForTest("credential-codex")
	if got, want := values[materialKeyAccessToken], "old-access"; got != want {
		t.Fatalf("access token = %q, want %q", got, want)
	}
}
