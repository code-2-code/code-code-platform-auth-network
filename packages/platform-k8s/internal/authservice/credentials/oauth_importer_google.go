package credentials

import (
	"context"
	"strings"

	credentialcontract "code-code.internal/platform-contract/credential"
)

type oauthValuesApplier func(
	importer *OAuthCredentialImporter,
	ctx context.Context,
	values map[string]string,
	request *credentialcontract.OAuthImportRequest,
	artifact *credentialcontract.OAuthArtifact,
) error

var oauthValueAppliers = map[string]oauthValuesApplier{}

func registerOAuthValueApplier(cliID string, applier oauthValuesApplier) {
	trimmedCLIID := strings.TrimSpace(cliID)
	if trimmedCLIID == "" || applier == nil {
		return
	}
	oauthValueAppliers[trimmedCLIID] = applier
}

func (i *OAuthCredentialImporter) applySpecializedOAuthValues(
	ctx context.Context,
	values map[string]string,
	request *credentialcontract.OAuthImportRequest,
	artifact *credentialcontract.OAuthArtifact,
) error {
	if i == nil || values == nil || request == nil || artifact == nil {
		return nil
	}
	cliID := strings.TrimSpace(string(request.CliID))
	if applier, ok := oauthValueAppliers[cliID]; ok {
		return applier(i, ctx, values, request, artifact)
	}
	return nil
}

func applyGoogleOAuthValues(values map[string]string, projectID string, tierName string) {
	if values == nil {
		return
	}
	if strings.TrimSpace(projectID) == "" && strings.TrimSpace(tierName) == "" {
		return
	}
	if strings.TrimSpace(projectID) != "" {
		values[materialKeyProjectID] = projectID
	}
	if strings.TrimSpace(tierName) != "" {
		values[materialKeyTierName] = tierName
	}
}

func (i *OAuthCredentialImporter) existingOAuthMaterialValue(ctx context.Context, credentialID string, materialKey string) string {
	if i == nil || i.credentials == nil || i.credentials.materialStore == nil || strings.TrimSpace(credentialID) == "" {
		return ""
	}
	values, err := i.credentials.materialStore.ReadValues(ctx, strings.TrimSpace(credentialID))
	if err != nil {
		return ""
	}
	return getOptionalValue(values, materialKey)
}
