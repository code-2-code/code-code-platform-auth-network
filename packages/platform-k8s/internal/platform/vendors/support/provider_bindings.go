package support

import (
	"strings"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	"google.golang.org/protobuf/proto"
)

func normalizeProviderBindings(vendor *supportv1.Vendor) {
	if vendor == nil {
		return
	}
	for _, binding := range vendor.GetProviderBindings() {
		normalizeProviderBinding(vendor, binding)
	}
}

func normalizeProviderBinding(vendor *supportv1.Vendor, binding *supportv1.VendorProviderBinding) {
	if vendor == nil || binding == nil {
		return
	}
	current := binding.GetProviderBinding()
	if current == nil {
		current = &supportv1.ProviderBinding{}
		binding.ProviderBinding = current
	}
	if strings.TrimSpace(current.GetSurfaceId()) == "" {
		current.SurfaceId = BindingSurfaceID(binding)
	}
	if strings.TrimSpace(current.GetModelCatalogProbeId()) == "" {
		current.ModelCatalogProbeId = defaultModelCatalogProbeID(vendor, binding)
	}
	if strings.TrimSpace(current.GetQuotaProbeId()) == "" {
		current.QuotaProbeId = defaultQuotaProbeID(binding)
	}
	if strings.TrimSpace(current.GetEgressPolicyId()) == "" {
		current.EgressPolicyId = defaultEgressPolicyID(vendor)
	}
	if strings.TrimSpace(current.GetHeaderRewritePolicyId()) == "" {
		current.HeaderRewritePolicyId = current.GetEgressPolicyId()
	}
}

func cloneProviderBindings(vendor *supportv1.Vendor) []*supportv1.VendorProviderBinding {
	if vendor == nil || len(vendor.GetProviderBindings()) == 0 {
		return nil
	}
	out := make([]*supportv1.VendorProviderBinding, 0, len(vendor.GetProviderBindings()))
	for _, binding := range vendor.GetProviderBindings() {
		if binding == nil {
			continue
		}
		out = append(out, proto.Clone(binding).(*supportv1.VendorProviderBinding))
	}
	return out
}

func BindingForSurfaceID(vendor *supportv1.Vendor, surfaceID string) (*supportv1.VendorProviderBinding, bool) {
	surfaceID = strings.TrimSpace(surfaceID)
	if surfaceID == "" || vendor == nil {
		return nil, false
	}
	for _, binding := range vendor.GetProviderBindings() {
		if BindingSurfaceID(binding) == surfaceID {
			return proto.Clone(binding).(*supportv1.VendorProviderBinding), true
		}
		for _, template := range binding.GetSurfaceTemplates() {
			if strings.TrimSpace(template.GetSurfaceId()) == surfaceID {
				return proto.Clone(binding).(*supportv1.VendorProviderBinding), true
			}
		}
	}
	return nil, false
}

func SupportsModelCatalogProbe(binding *supportv1.VendorProviderBinding) bool {
	if binding == nil {
		return false
	}
	if binding.GetModelDiscovery() != nil && binding.GetModelDiscovery().GetActiveDiscovery() != nil {
		return true
	}
	for _, template := range binding.GetSurfaceTemplates() {
		if len(template.GetBootstrapCatalog().GetModels()) > 0 {
			return true
		}
	}
	return false
}

func SupportsQuotaProbe(binding *supportv1.VendorProviderBinding) bool {
	if binding == nil {
		return false
	}
	return observabilityHasActiveQuery(binding.GetObservability())
}

func BindingSurfaceID(binding *supportv1.VendorProviderBinding) string {
	if binding == nil {
		return ""
	}
	if current := strings.TrimSpace(binding.GetProviderBinding().GetSurfaceId()); current != "" {
		return current
	}
	value := ""
	for _, template := range binding.GetSurfaceTemplates() {
		surfaceID := strings.TrimSpace(template.GetSurfaceId())
		if surfaceID == "" {
			continue
		}
		if value == "" {
			value = surfaceID
			continue
		}
		if value != surfaceID {
			return ""
		}
	}
	return value
}

func defaultModelCatalogProbeID(vendor *supportv1.Vendor, binding *supportv1.VendorProviderBinding) string {
	if surfaceID := strings.TrimSpace(BindingSurfaceID(binding)); surfaceID != "" {
		return surfaceID
	}
	if vendorID := strings.TrimSpace(vendor.GetVendor().GetVendorId()); vendorID != "" {
		return vendorID
	}
	return ""
}

func defaultQuotaProbeID(binding *supportv1.VendorProviderBinding) string {
	if collectorID := firstActiveQueryCollectorID(binding.GetObservability()); collectorID != "" {
		return collectorID
	}
	return ""
}

func defaultEgressPolicyID(vendor *supportv1.Vendor) string {
	if vendorID := strings.TrimSpace(vendor.GetVendor().GetVendorId()); vendorID != "" {
		return "vendor." + vendorID
	}
	return ""
}

func firstActiveQueryCollectorID(capability *observabilityv1.ObservabilityCapability) string {
	for _, profile := range capability.GetProfiles() {
		activeQuery := profile.GetActiveQuery()
		if activeQuery == nil {
			continue
		}
		if collectorID := strings.TrimSpace(activeQuery.GetCollectorId()); collectorID != "" {
			return collectorID
		}
	}
	return ""
}
