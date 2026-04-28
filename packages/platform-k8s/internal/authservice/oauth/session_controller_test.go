package oauth

import (
	"context"
	"testing"
	"time"

	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSessionReconcilerWaitsForInitialStatus(t *testing.T) {
	client := newOAuthSessionManagerTestClient()
	resource := &platformv1alpha1.OAuthAuthorizationSessionResource{
		TypeMeta: metav1.TypeMeta{
			APIVersion: platformv1alpha1.GroupVersion.String(),
			Kind:       platformv1alpha1.KindOAuthAuthorizationSessionResource,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "session-uninitialized-1",
			Namespace:  "code-code",
			Finalizers: []string{OAuthSessionFinalizer},
		},
		Spec: platformv1alpha1.OAuthAuthorizationSessionSpec{
			SessionID: "session-uninitialized-1",
			CliID:     "codex",
			Flow:      platformv1alpha1.OAuthAuthorizationSessionFlowCode,
		},
	}
	if err := client.Create(context.Background(), resource); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	store, err := NewOAuthSessionStore(client, client, "code-code")
	if err != nil {
		t.Fatalf("NewOAuthSessionStore() error = %v", err)
	}
	reconciler, err := NewSessionReconciler(SessionReconcilerConfig{
		Client:       client,
		Namespace:    "code-code",
		Executor:     &SessionExecutor{},
		SessionStore: store,
	})
	if err != nil {
		t.Fatalf("NewSessionReconciler() error = %v", err)
	}

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "code-code", Name: "session-uninitialized-1"}})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result != (ctrl.Result{}) {
		t.Fatalf("Reconcile() result = %+v, want empty", result)
	}
	stored := &platformv1alpha1.OAuthAuthorizationSessionResource{}
	if err := client.Get(context.Background(), ctrlclient.ObjectKeyFromObject(resource), stored); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if stored.Status.Phase != "" {
		t.Fatalf("phase = %q, want empty", stored.Status.Phase)
	}
}

func TestPollIntervalDuration(t *testing.T) {
	tests := []struct {
		name     string
		next     int32
		fallback int32
		want     time.Duration
	}{
		{name: "next interval wins", next: 12, fallback: 5, want: 12 * time.Second},
		{name: "fallback interval used", next: 0, fallback: 7, want: 7 * time.Second},
		{name: "default interval used", next: 0, fallback: 0, want: 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pollIntervalDuration(tt.next, tt.fallback); got != tt.want {
				t.Fatalf("pollIntervalDuration() = %s, want %s", got, tt.want)
			}
		})
	}
}
