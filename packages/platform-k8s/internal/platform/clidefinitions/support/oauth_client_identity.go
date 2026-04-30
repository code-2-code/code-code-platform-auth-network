package support

import (
	"fmt"
	"strings"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

const clientVersionTemplateVariable = "${client_version}"

func ValidateOAuthClientIdentity(pkg *supportv1.CLI) error {
	if pkg == nil {
		return nil
	}
	officialVersionSource := pkg.GetOfficialVersionSource()
	if err := validateOfficialVersionSource(officialVersionSource); err != nil {
		return fmt.Errorf("platformk8s: invalid cli support for %q: %w", pkg.GetCliId(), err)
	}
	if pkg.GetOauth() == nil {
		return nil
	}
	identity := pkg.GetOauth().GetClientIdentity()
	if identity == nil {
		return nil
	}
	if err := validateClientIdentityTemplate("model_catalog_user_agent_template", identity.GetModelCatalogUserAgentTemplate(), officialVersionSource); err != nil {
		return fmt.Errorf("platformk8s: invalid cli oauth client identity for %q: %w", pkg.GetCliId(), err)
	}
	if err := validateClientIdentityTemplate("observability_user_agent_template", identity.GetObservabilityUserAgentTemplate(), officialVersionSource); err != nil {
		return fmt.Errorf("platformk8s: invalid cli oauth client identity for %q: %w", pkg.GetCliId(), err)
	}
	return nil
}

func validateOfficialVersionSource(source *supportv1.OfficialVersionSource) error {
	if source == nil {
		return nil
	}
	switch typed := source.GetSource().(type) {
	case *supportv1.OfficialVersionSource_NpmDistTag:
		if strings.TrimSpace(typed.NpmDistTag.GetPackageName()) == "" {
			return fmt.Errorf("npm_dist_tag.package_name is required")
		}
	case *supportv1.OfficialVersionSource_HomebrewCask:
		if strings.TrimSpace(typed.HomebrewCask.GetCask()) == "" {
			return fmt.Errorf("homebrew_cask.cask is required")
		}
	default:
		return fmt.Errorf("official_version_source is required")
	}
	return nil
}

func validateClientIdentityTemplate(
	fieldName string,
	template string,
	source *supportv1.OfficialVersionSource,
) error {
	trimmed := strings.TrimSpace(template)
	if trimmed == "" {
		return nil
	}
	if strings.Contains(trimmed, clientVersionTemplateVariable) && source == nil {
		return fmt.Errorf("%s requires official_version_source", fieldName)
	}
	rendered := strings.ReplaceAll(trimmed, clientVersionTemplateVariable, "0.0.0")
	if strings.Contains(rendered, "${") {
		return fmt.Errorf("%s contains unsupported template variable", fieldName)
	}
	return nil
}
