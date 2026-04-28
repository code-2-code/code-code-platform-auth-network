package credentials

import (
	"context"
	"strings"

	credentialcontract "code-code.internal/platform-contract/credential"
	"code-code.internal/platform-k8s/internal/supportservice/clidefinitions/codeassist"
)

func init() {
	registerOAuthValueApplier("gemini-cli", (*OAuthCredentialImporter).applyGeminiOAuthValues)
}

func (i *OAuthCredentialImporter) applyGeminiOAuthValues(
	ctx context.Context,
	values map[string]string,
	request *credentialcontract.OAuthImportRequest,
	artifact *credentialcontract.OAuthArtifact,
) error {
	projectID := i.existingOAuthMaterialValue(ctx, strings.TrimSpace(request.CredentialID), materialKeyProjectID)
	tierName := i.existingOAuthMaterialValue(ctx, strings.TrimSpace(request.CredentialID), materialKeyTierName)
	if strings.TrimSpace(artifact.AccessToken) != "" && i.httpClientFactory != nil {
		httpClient, err := i.httpClientFactory.NewClient(ctx)
		if err == nil {
			payload, err := codeassist.LoadGeminiCodeAssist(ctx, httpClient, artifact.AccessToken, projectID)
			if err == nil {
				if resolvedProjectID := codeassist.GeminiProjectID(payload); resolvedProjectID != "" {
					projectID = resolvedProjectID
				}
				if resolvedTierName := codeassist.GeminiTierName(payload); resolvedTierName != "" {
					tierName = resolvedTierName
				}
			}
		}
	}
	applyGoogleOAuthValues(values, projectID, tierName)
	return nil
}
