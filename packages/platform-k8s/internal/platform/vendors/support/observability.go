package support

import (
	observabilityv1 "code-code.internal/go-contract/observability/v1"
)

func observabilityHasActiveQuery(capability *observabilityv1.ObservabilityCapability) bool {
	if capability == nil {
		return false
	}
	for _, profile := range capability.GetProfiles() {
		if profile != nil && profile.GetActiveQuery() != nil {
			return true
		}
	}
	return false
}
