package oauth

import (
	"context"
	"fmt"

	"code-code.internal/platform-k8s/internal/cliruntimeservice/cliversions"
	"code-code.internal/platform-k8s/internal/platform/modelcatalogdiscovery"
)

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
