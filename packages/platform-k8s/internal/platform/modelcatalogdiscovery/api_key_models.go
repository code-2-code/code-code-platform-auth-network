package modelcatalogdiscovery

import (
	apiprotocolv1 "code-code.internal/go-contract/api_protocol/v1"
	modelcatalogdiscoveryv1 "code-code.internal/go-contract/model_catalog_discovery/v1"
)

const anthropicVersionHeaderValue = "2023-06-01"

func DefaultAPIKeyDiscoveryOperation(protocol apiprotocolv1.Protocol) *modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation {
	security := []*modelcatalogdiscoveryv1.ModelCatalogDiscoverySecurityRequirement{{
		Schemes: []modelcatalogdiscoveryv1.ModelCatalogDiscoverySecurityScheme{
			modelcatalogdiscoveryv1.ModelCatalogDiscoverySecurityScheme_MODEL_CATALOG_DISCOVERY_SECURITY_SCHEME_API_KEY,
		},
	}}
	switch protocol {
	case apiprotocolv1.Protocol_PROTOCOL_GEMINI:
		return &modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation{
			Path:         "models",
			ResponseKind: modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_GEMINI_MODELS,
			Security:     security,
		}
	default:
		return &modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation{
			Path:         "models",
			ResponseKind: modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_OPENAI_MODELS,
			Security:     security,
		}
	}
}
