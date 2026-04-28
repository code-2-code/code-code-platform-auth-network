// Package testutil provides Kubernetes test utilities for platform-k8s tests.
package testutil

import (
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// NewScheme returns a runtime.Scheme configured with all platform object types.
func NewScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = platformv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

// NewClient returns a fake controller-runtime client seeded with a sample
// provider definition and instance.
func NewClient(namespace string) ctrlclient.Client {
	return ctrlclientfake.NewClientBuilder().
		WithScheme(NewScheme()).
		Build()
}

// NewDiscoverClient returns a fake controller-runtime client with platform
// object types registered.
func NewDiscoverClient(namespace string) ctrlclient.Client {
	return ctrlclientfake.NewClientBuilder().
		WithScheme(NewScheme()).
		Build()
}

// NewEmptyClient returns a fake controller-runtime client with an empty store.
func NewEmptyClient() ctrlclient.Client {
	return ctrlclientfake.NewClientBuilder().
		WithScheme(NewScheme()).
		Build()
}
