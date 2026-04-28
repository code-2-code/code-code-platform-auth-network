package resourceops

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCreateResourceCreatesObject(t *testing.T) {
	t.Parallel()

	client := newResourceOpsTestClient()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "credential-1",
			Namespace: "code-code",
		},
		Data: map[string][]byte{
			"api_key": []byte("test-key"),
		},
	}

	if err := CreateResource(context.Background(), client, secret, "code-code", "credential-1"); err != nil {
		t.Fatalf("CreateResource() error = %v", err)
	}

	got := &corev1.Secret{}
	if err := client.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "code-code", Name: "credential-1"}, got); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(got.Data["api_key"]) != "test-key" {
		t.Fatalf("secret api_key = %q, want test-key", string(got.Data["api_key"]))
	}
}

func TestCreateResourceReturnsAlreadyExists(t *testing.T) {
	t.Parallel()

	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "credential-1",
			Namespace: "code-code",
		},
		Data: map[string][]byte{
			"api_key": []byte("existing"),
		},
	}
	client := newResourceOpsTestClient(existing)

	incoming := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "credential-1",
			Namespace: "code-code",
		},
		Data: map[string][]byte{
			"api_key": []byte("new-value"),
		},
	}
	err := CreateResource(context.Background(), client, incoming, "code-code", "credential-1")
	if err == nil {
		t.Fatal("CreateResource() error = nil, want already exists")
	}
	if !apierrors.IsAlreadyExists(err) {
		t.Fatalf("CreateResource() error = %v, want already exists", err)
	}
}

func newResourceOpsTestClient(objects ...ctrlclient.Object) ctrlclient.Client {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return ctrlclientfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		Build()
}
