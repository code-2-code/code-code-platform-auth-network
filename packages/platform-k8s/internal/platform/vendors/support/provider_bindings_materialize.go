package support

import (
	"strings"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	providerv1 "code-code.internal/go-contract/provider/v1"
	"google.golang.org/protobuf/proto"
)

type MaterializedSurfaceTarget struct {
	Runtime          *providerv1.ProviderSurfaceRuntime
	BootstrapCatalog *providerv1.ProviderModelCatalog
}

func MaterializeSurfaceTargets(vendor *supportv1.Vendor) []*MaterializedSurfaceTarget {
	if vendor == nil {
		return nil
	}
	out := []*MaterializedSurfaceTarget{}
	for _, binding := range vendor.GetProviderBindings() {
		if binding == nil {
			continue
		}
		bindingConfig := binding.GetProviderBinding()
		for _, template := range binding.GetSurfaceTemplates() {
			if template == nil {
				continue
			}
			runtime := template.GetRuntime()
			if runtime == nil {
				runtime = &providerv1.ProviderSurfaceRuntime{}
			} else {
				runtime = proto.Clone(runtime).(*providerv1.ProviderSurfaceRuntime)
			}
			if strings.TrimSpace(runtime.GetDisplayName()) == "" {
				runtime.DisplayName = strings.TrimSpace(template.GetSurfaceId())
			}
			if strings.TrimSpace(runtime.GetModelCatalogProbeId()) == "" {
				runtime.ModelCatalogProbeId = strings.TrimSpace(bindingConfig.GetModelCatalogProbeId())
			}
			if strings.TrimSpace(runtime.GetQuotaProbeId()) == "" {
				runtime.QuotaProbeId = strings.TrimSpace(bindingConfig.GetQuotaProbeId())
			}
			if strings.TrimSpace(runtime.GetEgressRulesetId()) == "" {
				runtime.EgressRulesetId = strings.TrimSpace(bindingConfig.GetEgressPolicyId())
			}
			runtime.Origin = providerv1.ProviderSurfaceOrigin_PROVIDER_SURFACE_ORIGIN_DERIVED
			out = append(out, &MaterializedSurfaceTarget{
				Runtime:          runtime,
				BootstrapCatalog: cloneBootstrapCatalog(template.GetBootstrapCatalog()),
			})
		}
	}
	return out
}

func MaterializeSurfaces(vendor *supportv1.Vendor) []*providerv1.ProviderSurfaceRuntime {
	out := []*providerv1.ProviderSurfaceRuntime{}
	for _, target := range MaterializeSurfaceTargets(vendor) {
		if target == nil || target.Runtime == nil {
			continue
		}
		out = append(out, proto.Clone(target.Runtime).(*providerv1.ProviderSurfaceRuntime))
	}
	return out
}

func MaterializeObservability(vendor *supportv1.Vendor, surfaceID string) *observabilityv1.ObservabilityCapability {
	if vendor == nil {
		return nil
	}
	bindings := selectBindings(vendor, surfaceID)
	if len(bindings) == 0 {
		return nil
	}
	if len(bindings) == 1 {
		return cloneObservability(bindings[0].GetObservability())
	}
	profiles := make([]*observabilityv1.ObservabilityProfile, 0)
	seen := map[string]struct{}{}
	for _, binding := range bindings {
		for _, profile := range binding.GetObservability().GetProfiles() {
			if profile == nil {
				continue
			}
			key := strings.TrimSpace(profile.GetProfileId())
			if key == "" {
				key = strings.TrimSpace(profile.GetDisplayName())
			}
			if key != "" {
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
			}
			profiles = append(profiles, proto.Clone(profile).(*observabilityv1.ObservabilityProfile))
		}
	}
	if len(profiles) == 0 {
		return nil
	}
	return &observabilityv1.ObservabilityCapability{Profiles: profiles}
}

func cloneBootstrapCatalog(catalog *providerv1.ProviderModelCatalog) *providerv1.ProviderModelCatalog {
	if catalog == nil {
		return nil
	}
	return proto.Clone(catalog).(*providerv1.ProviderModelCatalog)
}

func cloneObservability(capability *observabilityv1.ObservabilityCapability) *observabilityv1.ObservabilityCapability {
	if capability == nil {
		return nil
	}
	return proto.Clone(capability).(*observabilityv1.ObservabilityCapability)
}

func selectBindings(
	vendor *supportv1.Vendor,
	surfaceID string,
) []*supportv1.VendorProviderBinding {
	if vendor == nil {
		return nil
	}
	surfaceID = strings.TrimSpace(surfaceID)
	out := make([]*supportv1.VendorProviderBinding, 0, len(vendor.GetProviderBindings()))
	for _, binding := range vendor.GetProviderBindings() {
		if binding == nil {
			continue
		}
		if surfaceID != "" && !bindingHasSurfaceID(binding, surfaceID) {
			continue
		}
		if surfaceID != "" && BindingSurfaceID(binding) != surfaceID {
			continue
		}
		out = append(out, binding)
	}
	return out
}

func bindingHasSurfaceID(binding *supportv1.VendorProviderBinding, surfaceID string) bool {
	for _, template := range binding.GetSurfaceTemplates() {
		if strings.TrimSpace(template.GetSurfaceId()) == surfaceID {
			return true
		}
	}
	return false
}
