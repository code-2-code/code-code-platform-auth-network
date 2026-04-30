package modelcatalogdiscovery

import (
	"reflect"
	"testing"

	modelcatalogdiscoveryv1 "code-code.internal/go-contract/model_catalog_discovery/v1"
)

func TestParseModelIDsGeminiQuotaBuckets(t *testing.T) {
	t.Parallel()

	modelIDs, err := ParseModelIDs(
		[]byte(`{"buckets":[{"modelId":"gemini-2.5-pro"},{"modelId":"gemini-3-pro-preview"},{"modelId":"gemini-2.5-pro"}]}`),
		modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_GEMINI_QUOTA_BUCKETS,
	)
	if err != nil {
		t.Fatalf("ParseModelIDs() error = %v", err)
	}
	want := []string{"gemini-2.5-pro", "gemini-3-pro-preview"}
	if !reflect.DeepEqual(modelIDs, want) {
		t.Fatalf("modelIDs = %#v, want %#v", modelIDs, want)
	}
}

func TestParseModelIDsAntigravityModelsMap(t *testing.T) {
	t.Parallel()

	modelIDs, err := ParseModelIDs(
		[]byte(`{"models":{"gemini-2.5-flash":{},"gemini-3-flash-preview":{}}}`),
		modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_ANTIGRAVITY_MODELS_MAP,
	)
	if err != nil {
		t.Fatalf("ParseModelIDs() error = %v", err)
	}
	want := []string{"gemini-2.5-flash", "gemini-3-flash-preview"}
	if !reflect.DeepEqual(modelIDs, want) {
		t.Fatalf("modelIDs = %#v, want %#v", modelIDs, want)
	}
}

func TestParseModelIDsGeminiModels(t *testing.T) {
	t.Parallel()

	modelIDs, err := ParseModelIDs(
		[]byte(`{"models":[{"name":"models/gemini-2.5-pro-latest","baseModelId":"models/gemini-2.5-pro"},{"name":"models/gemini-2.5-flash-latest","baseModelId":"gemini-2.5-flash"},{"name":"models/text-embedding-004"}]}`),
		modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_GEMINI_MODELS,
	)
	if err != nil {
		t.Fatalf("ParseModelIDs() error = %v", err)
	}
	want := []string{"gemini-2.5-pro", "gemini-2.5-flash", "text-embedding-004"}
	if !reflect.DeepEqual(modelIDs, want) {
		t.Fatalf("modelIDs = %#v, want %#v", modelIDs, want)
	}
}

func TestParseModelIDsOpenAIModelsNormalizesModelsPrefix(t *testing.T) {
	t.Parallel()

	modelIDs, err := ParseModelIDs(
		[]byte(`{"data":[{"id":"models/gemini-2.5-pro"}],"models":[{"id":"models/gemini-2.5-flash"},{"id":"gpt-4.1"}]}`),
		modelcatalogdiscoveryv1.ModelCatalogDiscoveryResponseKind_MODEL_CATALOG_DISCOVERY_RESPONSE_KIND_OPENAI_MODELS,
	)
	if err != nil {
		t.Fatalf("ParseModelIDs() error = %v", err)
	}
	want := []string{"gemini-2.5-pro", "gemini-2.5-flash", "gpt-4.1"}
	if !reflect.DeepEqual(modelIDs, want) {
		t.Fatalf("modelIDs = %#v, want %#v", modelIDs, want)
	}
}
