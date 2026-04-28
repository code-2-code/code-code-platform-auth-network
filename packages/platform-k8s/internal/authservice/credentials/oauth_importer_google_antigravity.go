package credentials

import (
	"context"
	"fmt"
	"strings"

	credentialcontract "code-code.internal/platform-contract/credential"
	"code-code.internal/platform-k8s/internal/supportservice/clidefinitions/codeassist"
)

func init() {
	registerOAuthValueApplier("antigravity", (*OAuthCredentialImporter).applyAntigravityOAuthValues)
}

func (i *OAuthCredentialImporter) applyAntigravityOAuthValues(
	ctx context.Context,
	values map[string]string,
	request *credentialcontract.OAuthImportRequest,
	artifact *credentialcontract.OAuthArtifact,
) error {
	projectID := i.existingOAuthMaterialValue(ctx, strings.TrimSpace(request.CredentialID), materialKeyProjectID)
	tierName := i.existingOAuthMaterialValue(ctx, strings.TrimSpace(request.CredentialID), materialKeyTierName)
	if projectID == "" {
		if strings.TrimSpace(artifact.AccessToken) == "" {
			return fmt.Errorf("platformk8s: antigravity oauth import requires access token to resolve project id")
		}
		if i.httpClientFactory == nil {
			return fmt.Errorf("platformk8s: antigravity oauth import http client factory is nil")
		}
	}
	if strings.TrimSpace(artifact.AccessToken) != "" && i.httpClientFactory != nil {
		httpClient, err := i.httpClientFactory.NewClient(ctx)
		if err != nil {
			if projectID == "" {
				return fmt.Errorf("platformk8s: resolve antigravity project id http client: %w", err)
			}
			applyGoogleOAuthValues(values, projectID, tierName)
			return nil
		}
		payload, err := codeassist.LoadAntigravityCodeAssistWithProject(ctx, httpClient, artifact.AccessToken, projectID)
		if err != nil {
			if projectID == "" {
				return fmt.Errorf("platformk8s: resolve antigravity project id: %w", err)
			}
			applyGoogleOAuthValues(values, projectID, tierName)
			return nil
		}
		if resolvedProjectID := codeassist.GeminiProjectID(payload); resolvedProjectID != "" {
			projectID = resolvedProjectID
		}
		if resolvedTierName := codeassist.AntigravityTierName(payload); resolvedTierName != "" {
			tierName = resolvedTierName
		}
		if projectID == "" {
			if !codeassist.AntigravityShouldOnboard(payload) {
				return fmt.Errorf("platformk8s: resolve antigravity project id: %w", codeassist.AntigravityProjectResolutionError(payload))
			}
			resolvedProjectID, err := codeassist.OnboardAntigravityUserWithProject(ctx, httpClient, artifact.AccessToken, codeassist.AntigravityDefaultTierID(payload), projectID)
			if err != nil {
				if codeassist.IsAntigravityOnboardMissingProjectID(err) {
					return fmt.Errorf("platformk8s: onboard antigravity project id: %w", codeassist.AntigravityProjectResolutionError(payload))
				}
				return fmt.Errorf("platformk8s: onboard antigravity project id: %w", err)
			}
			projectID = resolvedProjectID
		}
	}
	if strings.TrimSpace(projectID) == "" {
		return fmt.Errorf("platformk8s: antigravity oauth import did not resolve project id")
	}
	applyGoogleOAuthValues(values, projectID, tierName)
	return nil
}
