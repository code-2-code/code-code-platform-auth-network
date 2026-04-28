package egresspolicies

import (
	"fmt"
	"strings"

	"code-code.internal/platform-k8s/internal/egressauthpolicy"
)

// EgressRuntimeConfig identifies the namespace that owns generated egress resources.
type EgressRuntimeConfig struct {
	Namespace                      string
	DynamicHeaderAuthzProviderName string
}

type egressRuntime struct {
	namespace                      string
	dynamicHeaderAuthzProviderName string
}

func newEgressRuntime(config EgressRuntimeConfig) (egressRuntime, error) {
	runtime := egressRuntime{
		namespace:                      strings.TrimSpace(config.Namespace),
		dynamicHeaderAuthzProviderName: strings.TrimSpace(config.DynamicHeaderAuthzProviderName),
	}
	if runtime.namespace == "" {
		return egressRuntime{}, fmt.Errorf("platformk8s/egressservice/egresspolicies: egress namespace is empty")
	}
	if runtime.dynamicHeaderAuthzProviderName == "" {
		runtime.dynamicHeaderAuthzProviderName = egressauthpolicy.BearerExtensionProviderName
	}
	return runtime, nil
}
