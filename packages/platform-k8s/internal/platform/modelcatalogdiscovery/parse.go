package modelcatalogdiscovery

import (
	"encoding/json"
	"sort"
	"strings"

	"code-code.internal/go-contract/domainerror"
	modelcatalogdiscoveryv1 "code-code.internal/go-contract/model_catalog_discovery/v1"
)

type openAIModelsPayload struct {
	Data   []openAIModelItem `json:"data"`
	Models []openAIModelItem `json:"models"`
}

type openAIModelItem struct {
	ID string `json:"id"`
}

type geminiModelsPayload struct {
	Models []geminiModelItem `json:"models"`
}

type geminiModelItem struct {
	Name        string `json:"name"`
	BaseModelID string `json:"baseModelId"`
}

type codexModelsPayload struct {
	Models []codexModelItem `json:"models"`
}

type codexModelItem struct {
	Slug string `json:"slug"`
}

type geminiQuotaPayload struct {
	Buckets []geminiQuotaBucket `json:"buckets"`
}

type geminiQuotaBucket struct {
	ModelID string `json:"modelId"`
}

type antigravityModelsPayload struct {
	Models map[string]json.RawMessage `json:"models"`
}

func ParseModelIDs(body []byte, responseKind modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind) ([]string, error) {
	switch responseKind {
	case modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_OPENAI_MODELS:
		var payload openAIModelsPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: decode openai models operation response failed: %v", err)
		}
		return collectModelIDs(
			func() []string {
				out := make([]string, 0, len(payload.Data)+len(payload.Models))
				for _, item := range payload.Data {
					out = append(out, normalizeProviderModelID(item.ID))
				}
				for _, item := range payload.Models {
					out = append(out, normalizeProviderModelID(item.ID))
				}
				return out
			}(),
		), nil
	case modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_CODEX_MODELS:
		var payload codexModelsPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: decode codex models operation response failed: %v", err)
		}
		slugs := make([]string, 0, len(payload.Models))
		for _, model := range payload.Models {
			slugs = append(slugs, model.Slug)
		}
		return collectModelIDs(slugs), nil
	case modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_GEMINI_QUOTA_BUCKETS:
		var payload geminiQuotaPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: decode gemini quota operation response failed: %v", err)
		}
		modelIDs := make([]string, 0, len(payload.Buckets))
		for _, bucket := range payload.Buckets {
			modelIDs = append(modelIDs, bucket.ModelID)
		}
		return collectModelIDs(modelIDs), nil
	case modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_ANTIGRAVITY_MODELS_MAP:
		var payload antigravityModelsPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: decode antigravity models operation response failed: %v", err)
		}
		modelIDs := make([]string, 0, len(payload.Models))
		for modelID := range payload.Models {
			modelIDs = append(modelIDs, modelID)
		}
		sort.Strings(modelIDs)
		return collectModelIDs(modelIDs), nil
	case modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_GEMINI_MODELS:
		var payload geminiModelsPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: decode gemini models operation response failed: %v", err)
		}
		modelIDs := make([]string, 0, len(payload.Models))
		for _, model := range payload.Models {
			modelID := normalizeProviderModelID(model.BaseModelID)
			if modelID == "" {
				modelID = normalizeProviderModelID(model.Name)
			}
			modelIDs = append(modelIDs, modelID)
		}
		return collectModelIDs(modelIDs), nil
	default:
		return nil, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: unsupported operation response kind %s", responseKind.String())
	}
}

func normalizeProviderModelID(value string) string {
	modelID := strings.TrimSpace(value)
	if strings.HasPrefix(modelID, "models/") {
		modelID = strings.TrimPrefix(modelID, "models/")
	}
	return strings.TrimSpace(modelID)
}

func collectModelIDs(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		modelID := strings.TrimSpace(value)
		if modelID == "" {
			continue
		}
		if _, ok := seen[modelID]; ok {
			continue
		}
		seen[modelID] = struct{}{}
		out = append(out, modelID)
	}
	return out
}
