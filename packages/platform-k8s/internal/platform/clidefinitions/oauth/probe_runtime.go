package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	modelv1 "code-code.internal/go-contract/model/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	providerv1 "code-code.internal/go-contract/provider/v1"
	"code-code.internal/platform-k8s/internal/cliruntimeservice/cliversions"
	"code-code.internal/platform-k8s/internal/platform/modelcatalogdiscovery"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func BuildOAuthProbeCatalog(
	pkg *supportv1.CLI,
	modelIDs []string,
	now time.Time,
) (*providerv1.ProviderModelCatalog, error) {
	vendorID := strings.TrimSpace(pkg.GetVendorId())
	if vendorID == "" {
		return nil, fmt.Errorf("platformk8s/clidefinitions: oauth operation vendor id is empty for %q", pkg.GetCliId())
	}
	entries := oauthProbeCatalogEntries(pkg, vendorID, modelIDs)
	if len(entries) == 0 {
		return nil, fmt.Errorf("platformk8s/clidefinitions: oauth operation catalog is empty for %q", pkg.GetCliId())
	}
	return &providerv1.ProviderModelCatalog{
		Models:    entries,
		Source:    providerv1.CatalogSource_CATALOG_SOURCE_PROTOCOL_QUERY,
		UpdatedAt: timestamppb.New(now.UTC()),
	}, nil
}

func oauthProbeCatalogEntries(
	pkg *supportv1.CLI,
	vendorID string,
	modelIDs []string,
) []*providerv1.ProviderModelCatalogEntry {
	seen := map[string]struct{}{}
	normalizedIDs := make([]string, 0, len(modelIDs))
	for _, rawModelID := range modelIDs {
		modelID := strings.TrimSpace(rawModelID)
		if modelID == "" {
			continue
		}
		if _, ok := seen[modelID]; ok {
			continue
		}
		seen[modelID] = struct{}{}
		normalizedIDs = append(normalizedIDs, modelID)
	}
	normalizedIDs = filterOAuthProbeModelIDs(pkg, normalizedIDs)
	fallback, _ := ResolveOAuthModelCatalog(pkg)
	if fallback == nil || len(fallback.GetModels()) == 0 {
		return oauthProbeRawEntries(vendorID, normalizedIDs)
	}
	byProviderModelID := map[string]*providerv1.ProviderModelCatalogEntry{}
	byModelID := map[string]*providerv1.ProviderModelCatalogEntry{}
	for _, entry := range fallback.GetModels() {
		if entry == nil {
			continue
		}
		if providerModelID := strings.TrimSpace(entry.GetProviderModelId()); providerModelID != "" {
			byProviderModelID[providerModelID] = proto.Clone(entry).(*providerv1.ProviderModelCatalogEntry)
		}
		if modelID := strings.TrimSpace(entry.GetModelRef().GetModelId()); modelID != "" {
			byModelID[modelID] = proto.Clone(entry).(*providerv1.ProviderModelCatalogEntry)
		}
	}
	entries := make([]*providerv1.ProviderModelCatalogEntry, 0, len(normalizedIDs))
	for _, modelID := range normalizedIDs {
		if entry, ok := byProviderModelID[modelID]; ok {
			entries = append(entries, entry)
			continue
		}
		if entry, ok := byModelID[modelID]; ok {
			entries = append(entries, entry)
			continue
		}
		entries = append(entries, &providerv1.ProviderModelCatalogEntry{
			ProviderModelId: modelID,
			ModelRef: &modelv1.ModelRef{
				VendorId: vendorID,
				ModelId:  modelID,
			},
		})
	}
	return entries
}

func oauthProbeRawEntries(vendorID string, modelIDs []string) []*providerv1.ProviderModelCatalogEntry {
	entries := make([]*providerv1.ProviderModelCatalogEntry, 0, len(modelIDs))
	for _, modelID := range modelIDs {
		entries = append(entries, &providerv1.ProviderModelCatalogEntry{
			ProviderModelId: modelID,
			ModelRef: &modelv1.ModelRef{
				VendorId: vendorID,
				ModelId:  modelID,
			},
		})
	}
	return entries
}

func ResolveOAuthDiscoveryDynamicValues(
	ctx context.Context,
	versionStore cliversions.Store,
	cliID string,
) (modelcatalogdiscovery.DynamicValues, error) {
	values := modelcatalogdiscovery.DynamicValues{}
	if versionStore == nil {
		return modelcatalogdiscovery.DynamicValues{}, fmt.Errorf("platformk8s/clidefinitions: cli version store is nil")
	}
	if version, err := cliversions.Resolve(ctx, versionStore, cliID); err != nil {
		return modelcatalogdiscovery.DynamicValues{}, err
	} else if version != "" {
		values.ClientVersion = version
	}
	return values, nil
}
