package support

import (
	"strings"

	apiprotocolv1 "code-code.internal/go-contract/api_protocol/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	providerv1 "code-code.internal/go-contract/provider/v1"
	"google.golang.org/protobuf/proto"
)

func normalizeSurfaces(vendor *supportv1.Vendor) {
	if vendor == nil {
		return
	}
	vendorID := strings.TrimSpace(vendor.GetVendor().GetVendorId())
	for _, surface := range vendor.GetSurfaces() {
		normalizeSurface(surface, vendorID)
	}
}

func normalizeSurface(surface *supportv1.Surface, vendorID string) {
	if surface == nil {
		return
	}
	surface.SurfaceId = normalizeSurfaceID(vendorID, surface.GetSurfaceId())
	if strings.TrimSpace(surface.GetProductInfoId()) == "" {
		surface.ProductInfoId = vendorID
	} else {
		surface.ProductInfoId = strings.TrimSpace(surface.GetProductInfoId())
	}
	if strings.TrimSpace(surface.GetEgressPolicyId()) == "" {
		surface.EgressPolicyId = defaultEgressPolicyID(vendorID)
	} else {
		surface.EgressPolicyId = strings.TrimSpace(surface.GetEgressPolicyId())
	}
	if strings.TrimSpace(surface.GetAuthPolicyId()) == "" {
		surface.AuthPolicyId = surface.GetEgressPolicyId()
	} else {
		surface.AuthPolicyId = strings.TrimSpace(surface.GetAuthPolicyId())
	}
	surface.ModelCatalogProbeId = strings.TrimSpace(surface.GetModelCatalogProbeId())
	surface.QuotaProbeId = strings.TrimSpace(surface.GetQuotaProbeId())
	surface.ObservabilityPolicyId = strings.TrimSpace(surface.GetObservabilityPolicyId())
	if surface.GetObservabilityPolicyId() == "" {
		surface.ObservabilityPolicyId = surface.GetEgressPolicyId()
	}
	if surface.GetModelCatalogProbeId() == "" {
		if _, ok := SurfaceDefaultAPIEndpoint(surface); ok {
			surface.ModelCatalogProbeId = surfaceModelCatalogProbeID(surface.GetSurfaceId())
		}
	}
}

func cloneSurfaces(vendor *supportv1.Vendor) []*supportv1.Surface {
	if vendor == nil || len(vendor.GetSurfaces()) == 0 {
		return nil
	}
	out := make([]*supportv1.Surface, 0, len(vendor.GetSurfaces()))
	for _, surface := range vendor.GetSurfaces() {
		if surface == nil {
			continue
		}
		out = append(out, proto.Clone(surface).(*supportv1.Surface))
	}
	return out
}

func SurfaceForID(vendor *supportv1.Vendor, surfaceID string) (*supportv1.Surface, bool) {
	surfaceID = strings.TrimSpace(surfaceID)
	if surfaceID == "" || vendor == nil {
		return nil, false
	}
	for _, surface := range vendor.GetSurfaces() {
		if strings.TrimSpace(surface.GetSurfaceId()) == surfaceID {
			return proto.Clone(surface).(*supportv1.Surface), true
		}
	}
	return nil, false
}

func SurfaceProductInfoID(vendor *supportv1.Vendor, surface *supportv1.Surface) string {
	if productInfoID := strings.TrimSpace(surface.GetProductInfoId()); productInfoID != "" {
		return productInfoID
	}
	return strings.TrimSpace(vendor.GetVendor().GetVendorId())
}

func SurfaceModelCatalogProbeID(surface *supportv1.Surface) string {
	if surface == nil {
		return ""
	}
	return strings.TrimSpace(surface.GetModelCatalogProbeId())
}

func SurfaceQuotaProbeID(surface *supportv1.Surface) string {
	if surface == nil {
		return ""
	}
	return strings.TrimSpace(surface.GetQuotaProbeId())
}

func SurfaceEgressPolicyID(vendor *supportv1.Vendor, surface *supportv1.Surface) string {
	if policyID := strings.TrimSpace(surface.GetEgressPolicyId()); policyID != "" {
		return policyID
	}
	return defaultEgressPolicyID(strings.TrimSpace(vendor.GetVendor().GetVendorId()))
}

func SurfaceAuthPolicyID(vendor *supportv1.Vendor, surface *supportv1.Surface) string {
	if policyID := strings.TrimSpace(surface.GetAuthPolicyId()); policyID != "" {
		return policyID
	}
	return SurfaceEgressPolicyID(vendor, surface)
}

func SurfaceObservabilityPolicyID(surface *supportv1.Surface) string {
	if surface == nil {
		return ""
	}
	return strings.TrimSpace(surface.GetObservabilityPolicyId())
}

func SurfaceSupportsModelCatalogProbe(surface *supportv1.Surface) bool {
	if surface == nil {
		return false
	}
	return SurfaceModelCatalogProbeID(surface) != ""
}

func SurfaceSupportsQuotaProbe(surface *supportv1.Surface) bool {
	return SurfaceQuotaProbeID(surface) != ""
}

func SurfaceDefaultAPIEndpoint(surface *supportv1.Surface) (*supportv1.ApiEndpoint, bool) {
	for _, endpoint := range surface.GetApi().GetApiEndpoints() {
		if endpoint == nil {
			continue
		}
		if endpoint.GetProtocol() == apiprotocolv1.Protocol_PROTOCOL_UNSPECIFIED {
			continue
		}
		if strings.TrimSpace(endpoint.GetBaseUrl()) == "" {
			continue
		}
		return endpoint, true
	}
	return nil, false
}

func SurfaceSupportsProtocol(surface *supportv1.Surface, protocol apiprotocolv1.Protocol) bool {
	if protocol == apiprotocolv1.Protocol_PROTOCOL_UNSPECIFIED {
		return true
	}
	for _, endpoint := range surface.GetApi().GetApiEndpoints() {
		if endpoint.GetProtocol() == protocol && strings.TrimSpace(endpoint.GetBaseUrl()) != "" {
			return true
		}
	}
	return false
}

func SurfaceEndpoints(surface *supportv1.Surface) []*providerv1.ProviderEndpoint {
	if surface == nil {
		return nil
	}
	if cliID := strings.TrimSpace(surface.GetCli().GetCliId()); cliID != "" {
		return []*providerv1.ProviderEndpoint{{
			Type: providerv1.ProviderEndpointType_PROVIDER_ENDPOINT_TYPE_CLI,
			Shape: &providerv1.ProviderEndpoint_Cli{Cli: &providerv1.ProviderCliEndpoint{
				CliId: cliID,
			}},
		}}
	}
	out := []*providerv1.ProviderEndpoint{}
	for _, endpoint := range surface.GetApi().GetApiEndpoints() {
		if endpoint == nil || endpoint.GetProtocol() == apiprotocolv1.Protocol_PROTOCOL_UNSPECIFIED || strings.TrimSpace(endpoint.GetBaseUrl()) == "" {
			continue
		}
		out = append(out, &providerv1.ProviderEndpoint{
			Type: providerv1.ProviderEndpointType_PROVIDER_ENDPOINT_TYPE_API,
			Shape: &providerv1.ProviderEndpoint_Api{Api: &providerv1.ProviderApiEndpoint{
				BaseUrl:  strings.TrimSpace(endpoint.GetBaseUrl()),
				Protocol: endpoint.GetProtocol(),
			}},
		})
	}
	return out
}

func surfaceModelCatalogProbeID(surfaceID string) string {
	surfaceID = strings.TrimSpace(surfaceID)
	if surfaceID == "" {
		return ""
	}
	return "surface." + surfaceID
}

func normalizeSurfaceID(vendorID string, surfaceID string) string {
	vendorID = strings.TrimSpace(vendorID)
	surfaceID = strings.TrimSpace(surfaceID)
	if vendorID == "" || surfaceID == "" {
		return surfaceID
	}
	if surfaceID == vendorID || strings.HasPrefix(surfaceID, vendorID+"-") {
		return surfaceID
	}
	return vendorID + "-" + surfaceID
}

func defaultEgressPolicyID(vendorID string) string {
	vendorID = strings.TrimSpace(vendorID)
	if vendorID == "" {
		return ""
	}
	return "vendor." + vendorID
}
