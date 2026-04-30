package support

import (
	"strings"

	apiprotocolv1 "code-code.internal/go-contract/api_protocol/v1"
	credentialv1 "code-code.internal/go-contract/credential/v1"
	observabilityv1 "code-code.internal/go-contract/observability/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	"google.golang.org/protobuf/proto"
)

func normalizeOAuthProviderBinding(cli *supportv1.CLI) {
	if cli == nil || cli.GetOauth() == nil {
		return
	}
	current := cli.GetOauth().GetProviderBinding()
	if current == nil {
		current = &supportv1.ProviderBinding{}
		cli.GetOauth().ProviderBinding = current
	}
	if strings.TrimSpace(current.GetSurfaceId()) == "" {
		current.SurfaceId = defaultOAuthSurfaceID(cli)
	}
	if strings.TrimSpace(current.GetModelCatalogProbeId()) == "" {
		current.ModelCatalogProbeId = cliDefaultModelCatalogProbeID(cli)
	}
	if strings.TrimSpace(current.GetQuotaProbeId()) == "" {
		current.QuotaProbeId = cliDefaultQuotaProbeID(cli)
	}
	if strings.TrimSpace(current.GetEgressPolicyId()) == "" {
		current.EgressPolicyId = cliDefaultEgressPolicyID(cli)
	}
	if strings.TrimSpace(current.GetHeaderRewritePolicyId()) == "" {
		current.HeaderRewritePolicyId = current.GetEgressPolicyId()
	}
}

func OAuthProviderBinding(cli *supportv1.CLI) *supportv1.ProviderBinding {
	if cli == nil || cli.GetOauth() == nil || cli.GetOauth().GetProviderBinding() == nil {
		return nil
	}
	return proto.Clone(cli.GetOauth().GetProviderBinding()).(*supportv1.ProviderBinding)
}

func OAuthProviderSurfaceID(cli *supportv1.CLI) string {
	binding := OAuthProviderBinding(cli)
	if binding == nil {
		return defaultOAuthSurfaceID(cli)
	}
	if value := strings.TrimSpace(binding.GetSurfaceId()); value != "" {
		return value
	}
	return defaultOAuthSurfaceID(cli)
}

func OAuthModelCatalogProbeID(cli *supportv1.CLI) string {
	binding := OAuthProviderBinding(cli)
	if binding == nil {
		return cliDefaultModelCatalogProbeID(cli)
	}
	if value := strings.TrimSpace(binding.GetModelCatalogProbeId()); value != "" {
		return value
	}
	return cliDefaultModelCatalogProbeID(cli)
}

func OAuthQuotaProbeID(cli *supportv1.CLI) string {
	binding := OAuthProviderBinding(cli)
	if binding == nil {
		return cliDefaultQuotaProbeID(cli)
	}
	if value := strings.TrimSpace(binding.GetQuotaProbeId()); value != "" {
		return value
	}
	return cliDefaultQuotaProbeID(cli)
}

func OAuthEgressPolicyID(cli *supportv1.CLI) string {
	binding := OAuthProviderBinding(cli)
	if binding == nil {
		return cliDefaultEgressPolicyID(cli)
	}
	if value := strings.TrimSpace(binding.GetEgressPolicyId()); value != "" {
		return value
	}
	return cliDefaultEgressPolicyID(cli)
}

func OAuthHeaderRewritePolicyID(cli *supportv1.CLI) string {
	binding := OAuthProviderBinding(cli)
	if binding == nil {
		return cliDefaultHeaderRewritePolicyID(cli)
	}
	if value := strings.TrimSpace(binding.GetHeaderRewritePolicyId()); value != "" {
		return value
	}
	return cliDefaultHeaderRewritePolicyID(cli)
}

func OAuthSupportsModelCatalogProbe(cli *supportv1.CLI) bool {
	if cli == nil || cli.GetOauth() == nil || cli.GetOauth().GetModelCatalog() == nil {
		return false
	}
	return cli.GetOauth().GetModelCatalog().GetAuthenticatedDiscovery().GetOperation() != nil
}

func OAuthSupportsQuotaProbe(cli *supportv1.CLI) bool {
	if cli == nil || cli.GetOauth() == nil {
		return false
	}
	return observabilityHasActiveQuery(cli.GetOauth().GetObservability())
}

func cliDefaultModelCatalogProbeID(cli *supportv1.CLI) string {
	if discovery := cli.GetOauth().GetModelCatalog().GetAuthenticatedDiscovery(); discovery != nil {
		if collectorID := strings.TrimSpace(discovery.GetCollectorId()); collectorID != "" {
			return collectorID
		}
	}
	if surfaceID := strings.TrimSpace(OAuthProviderSurfaceID(cli)); surfaceID != "" {
		return surfaceID
	}
	return strings.TrimSpace(cli.GetCliId())
}

func defaultOAuthSurfaceID(cli *supportv1.CLI) string {
	if protocol := oauthPrimaryProtocol(cli); protocol != apiprotocolv1.Protocol_PROTOCOL_UNSPECIFIED {
		return surfaceIDForProtocol(protocol)
	}
	if vendorID := strings.TrimSpace(cli.GetVendorId()); vendorID == "google" {
		return "gemini"
	}
	return ""
}

func oauthPrimaryProtocol(cli *supportv1.CLI) apiprotocolv1.Protocol {
	if cli == nil {
		return apiprotocolv1.Protocol_PROTOCOL_UNSPECIFIED
	}
	if materialization, err := ResolveAuthMaterialization(cli, credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH, apiprotocolv1.Protocol_PROTOCOL_GEMINI); err == nil && materialization != nil {
		return apiprotocolv1.Protocol_PROTOCOL_GEMINI
	}
	for _, item := range cli.GetApiKeyProtocols() {
		if item == nil {
			continue
		}
		protocol := item.GetProtocol()
		if protocol == apiprotocolv1.Protocol_PROTOCOL_UNSPECIFIED {
			continue
		}
		return protocol
	}
	if strings.TrimSpace(cli.GetVendorId()) == "google" {
		return apiprotocolv1.Protocol_PROTOCOL_GEMINI
	}
	return apiprotocolv1.Protocol_PROTOCOL_UNSPECIFIED
}

func surfaceIDForProtocol(protocol apiprotocolv1.Protocol) string {
	switch protocol {
	case apiprotocolv1.Protocol_PROTOCOL_GEMINI:
		return "gemini"
	case apiprotocolv1.Protocol_PROTOCOL_ANTHROPIC:
		return "anthropic"
	case apiprotocolv1.Protocol_PROTOCOL_OPENAI_COMPATIBLE, apiprotocolv1.Protocol_PROTOCOL_OPENAI_RESPONSES:
		return "openai-compatible"
	default:
		return ""
	}
}

func cliDefaultQuotaProbeID(cli *supportv1.CLI) string {
	if collectorID := firstActiveQueryCollectorID(cli.GetOauth().GetObservability()); collectorID != "" {
		return collectorID
	}
	if cli.GetOauth().GetObservability() != nil {
		return strings.TrimSpace(cli.GetCliId())
	}
	return ""
}

func cliDefaultEgressPolicyID(cli *supportv1.CLI) string {
	if vendorID := strings.TrimSpace(cli.GetVendorId()); vendorID != "" && cli.GetOauth() != nil {
		return "cli." + vendorID + "-oauth"
	}
	if cliID := strings.TrimSpace(cli.GetCliId()); cliID != "" {
		return "cli." + cliID
	}
	return ""
}

func cliDefaultHeaderRewritePolicyID(cli *supportv1.CLI) string {
	if policyID := strings.TrimSpace(OAuthEgressPolicyID(cli)); policyID != "" {
		return policyID
	}
	return cliDefaultEgressPolicyID(cli)
}

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
