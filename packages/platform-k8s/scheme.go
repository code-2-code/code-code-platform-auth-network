package platformk8s

import (
	"code-code.internal/platform-k8s/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
)

// AddToScheme registers platform object types onto the supplied scheme so
// callers do not need to import platform-k8s internal packages directly.
func AddToScheme(scheme *runtime.Scheme) error {
	return v1alpha1.AddToScheme(scheme)
}
