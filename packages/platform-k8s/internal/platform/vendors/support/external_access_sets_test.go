package support

import (
	"slices"
	"testing"

	egressv1 "code-code.internal/go-contract/egress/v1"
)

func TestPresetExternalRuleSetsProjectToExternalAccessSets(t *testing.T) {
	sets := PresetExternalRuleSetAccessSets()
	if got, want := len(sets), 2; got != want {
		t.Fatalf("external rule sets = %d, want %d", got, want)
	}
	accessSet := sets[0]
	if got, want := accessSet.GetAccessSetId(), "support.external-rule-set.bootstrap"; got != want {
		t.Fatalf("access set id = %q, want %q", got, want)
	}
	if got, want := len(accessSet.GetExternalRules()), 14; got != want {
		t.Fatalf("external rules = %d, want %d", got, want)
	}
	if got, want := len(accessSet.GetServiceRules()), 14; got != want {
		t.Fatalf("service rules = %d, want %d", got, want)
	}
	if got, want := len(accessSet.GetHttpInspectionRules()), 0; got != want {
		t.Fatalf("http inspection rules = %d, want %d", got, want)
	}
	rawRule := externalRuleByDestination(t, accessSet, "support.external-rule-set.bootstrap.github-raw-content")
	if got, want := rawRule.GetHostMatch().GetHostExact(), "raw.githubusercontent.com"; got != want {
		t.Fatalf("raw host exact = %q, want %q", got, want)
	}
	openaiRule := externalRuleByDestination(t, accessSet, "protocol.openai-compatible.api")
	if got, want := openaiRule.GetHostMatch().GetHostExact(), "api.openai.com"; got != want {
		t.Fatalf("openai host exact = %q, want %q", got, want)
	}
	mistralRule := externalRuleByDestination(t, accessSet, "vendor.mistral.api")
	if got, want := mistralRule.GetHostMatch().GetHostExact(), "api.mistral.ai"; got != want {
		t.Fatalf("mistral host exact = %q, want %q", got, want)
	}
	if got, want := mistralRule.GetEgressPath().GetMode(), egressv1.EgressPathMode_EGRESS_PATH_MODE_PROXY; got != want {
		t.Fatalf("mistral egress path mode = %v, want %v", got, want)
	}
	if got, want := mistralRule.GetEgressPath().GetProxyEndpointId(), "preset-proxy"; got != want {
		t.Fatalf("mistral proxy endpoint = %q, want %q", got, want)
	}
	mistralServiceRule := serviceRuleByDestination(t, accessSet, "vendor.mistral.api")
	if got, want := mistralServiceRule.GetSourceServiceAccounts(), []string{
		"code-code/platform-agent-runtime-service",
		"code-code/platform-provider-service",
		"code-code/provider-host-blackbox-exporter",
	}; !slices.Equal(got, want) {
		t.Fatalf("mistral source service accounts = %v, want %v", got, want)
	}
	mistralConsoleRule := externalRuleByDestination(t, accessSet, "vendor.mistral.console")
	if got, want := mistralConsoleRule.GetHostMatch().GetHostExact(), "console.mistral.ai"; got != want {
		t.Fatalf("mistral console host exact = %q, want %q", got, want)
	}
	mistralConsoleServiceRule := serviceRuleByDestination(t, accessSet, "vendor.mistral.console")
	if got, want := mistralConsoleServiceRule.GetSourceServiceAccounts(), []string{"code-code/platform-provider-service"}; !slices.Equal(got, want) {
		t.Fatalf("mistral console source service accounts = %v, want %v", got, want)
	}
	mistralAdminRule := externalRuleByDestination(t, accessSet, "vendor.mistral.admin")
	if got, want := mistralAdminRule.GetHostMatch().GetHostExact(), "admin.mistral.ai"; got != want {
		t.Fatalf("mistral admin host exact = %q, want %q", got, want)
	}
	mistralAdminServiceRule := serviceRuleByDestination(t, accessSet, "vendor.mistral.admin")
	if got, want := mistralAdminServiceRule.GetSourceServiceAccounts(), []string{
		"code-code/platform-auth-service",
		"code-code/platform-provider-service",
	}; !slices.Equal(got, want) {
		t.Fatalf("mistral admin source service accounts = %v, want %v", got, want)
	}
	googleAIStudioRPCRule := externalRuleByDestination(t, accessSet, "vendor.google.aistudio.rpc")
	if got, want := googleAIStudioRPCRule.GetHostMatch().GetHostExact(), "alkalimakersuite-pa.clients6.google.com"; got != want {
		t.Fatalf("google ai studio rpc host exact = %q, want %q", got, want)
	}
	if got, want := googleAIStudioRPCRule.GetProtocol(), egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS; got != want {
		t.Fatalf("google ai studio rpc protocol = %v, want %v", got, want)
	}
	if got, want := googleAIStudioRPCRule.GetEgressPath().GetProxyEndpointId(), "preset-proxy"; got != want {
		t.Fatalf("google ai studio rpc proxy endpoint = %q, want %q", got, want)
	}
	googleAIStudioRPCServiceRule := serviceRuleByDestination(t, accessSet, "vendor.google.aistudio.rpc")
	if got, want := googleAIStudioRPCServiceRule.GetSourceServiceAccounts(), []string{"code-code/platform-provider-service"}; !slices.Equal(got, want) {
		t.Fatalf("google ai studio rpc source service accounts = %v, want %v", got, want)
	}
	googleGenerativeLanguageRule := externalRuleByDestination(t, accessSet, "vendor.google.generative-language-api")
	if got, want := googleGenerativeLanguageRule.GetHostMatch().GetHostExact(), "generativelanguage.googleapis.com"; got != want {
		t.Fatalf("google generative language host exact = %q, want %q", got, want)
	}
	if got, want := googleGenerativeLanguageRule.GetEgressPath().GetProxyEndpointId(), "preset-proxy"; got != want {
		t.Fatalf("google generative language proxy endpoint = %q, want %q", got, want)
	}
	googleGenerativeLanguageServiceRule := serviceRuleByDestination(t, accessSet, "vendor.google.generative-language-api")
	if got, want := googleGenerativeLanguageServiceRule.GetSourceServiceAccounts(), []string{
		"code-code/platform-provider-service",
		"code-code/provider-host-blackbox-exporter",
	}; !slices.Equal(got, want) {
		t.Fatalf("google generative language source service accounts = %v, want %v", got, want)
	}
	modelCatalogSet := sets[1]
	if got, want := modelCatalogSet.GetAccessSetId(), "support.external-rule-set.model-catalog-sources"; got != want {
		t.Fatalf("model catalog access set id = %q, want %q", got, want)
	}
	if got, want := len(modelCatalogSet.GetExternalRules()), 6; got != want {
		t.Fatalf("model catalog external rules = %d, want %d", got, want)
	}
	openrouterRule := externalRuleByDestination(t, modelCatalogSet, "support.external-rule-set.model-catalog-sources.openrouter")
	if got, want := openrouterRule.GetHostMatch().GetHostExact(), "openrouter.ai"; got != want {
		t.Fatalf("openrouter host exact = %q, want %q", got, want)
	}
	if got, want := openrouterRule.GetEgressPath().GetProxyEndpointId(), "preset-proxy"; got != want {
		t.Fatalf("openrouter proxy endpoint = %q, want %q", got, want)
	}
	openrouterServiceRule := serviceRuleByDestination(t, modelCatalogSet, "support.external-rule-set.model-catalog-sources.openrouter")
	if got, want := openrouterServiceRule.GetSourceServiceAccounts(), []string{"code-code/platform-model-service"}; !slices.Equal(got, want) {
		t.Fatalf("openrouter source service accounts = %v, want %v", got, want)
	}
}

func TestL7SmokeRuleSetIsParsedButNotStartupSynced(t *testing.T) {
	var smoke externalRuleSetConfig
	found := false
	for _, ruleSet := range presetExternalRuleSets {
		if ruleSet.RuleSetID == "support.external-rule-set.l7-smoke" {
			smoke = ruleSet
			found = true
			break
		}
	}
	if !found {
		t.Fatal("l7 smoke rule set not found")
	}
	if startupSyncEnabled(smoke.StartupSync) {
		t.Fatal("l7 smoke rule set startupSync = true, want false")
	}
	accessSet := externalAccessSetFromRuleSet(smoke)
	if got, want := len(accessSet.GetExternalRules()), 1; got != want {
		t.Fatalf("external rules = %d, want %d", got, want)
	}
	rule := accessSet.GetExternalRules()[0]
	if got, want := rule.GetProtocol(), egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS; got != want {
		t.Fatalf("protocol = %v, want %v", got, want)
	}
	if got, want := rule.GetHostMatch().GetHostExact(), "httpbin.org"; got != want {
		t.Fatalf("host exact = %q, want %q", got, want)
	}
	if got, want := len(accessSet.GetHttpInspectionRules()), 1; got != want {
		t.Fatalf("http inspection rules = %d, want %d", got, want)
	}
	inspectionRule := accessSet.GetHttpInspectionRules()[0]
	if got, want := inspectionRule.GetDestinationId(), "support.external-rule-set.l7-smoke.httpbin-headers"; got != want {
		t.Fatalf("inspection rule destination = %q, want %q", got, want)
	}
	if got, want := len(inspectionRule.GetRequestHeaders().GetSet()), 1; got != want {
		t.Fatalf("request header set = %d, want %d", got, want)
	}
	if got, want := len(inspectionRule.GetResponseHeaders().GetSet()), 1; got != want {
		t.Fatalf("response header set = %d, want %d", got, want)
	}
	if inspectionRule.GetDynamicHeaderAuthz() {
		t.Fatal("dynamic header authz = true, want false for static L7 smoke")
	}
}

func TestL7DynamicAuthzSmokeRuleSetIsParsedButNotStartupSynced(t *testing.T) {
	var smoke externalRuleSetConfig
	found := false
	for _, ruleSet := range presetExternalRuleSets {
		if ruleSet.RuleSetID == "support.external-rule-set.l7-dynamic-authz-smoke" {
			smoke = ruleSet
			found = true
			break
		}
	}
	if !found {
		t.Fatal("l7 dynamic authz smoke rule set not found")
	}
	if startupSyncEnabled(smoke.StartupSync) {
		t.Fatal("l7 dynamic authz smoke rule set startupSync = true, want false")
	}
	accessSet := externalAccessSetFromRuleSet(smoke)
	if got, want := len(accessSet.GetExternalRules()), 1; got != want {
		t.Fatalf("external rules = %d, want %d", got, want)
	}
	if got, want := len(accessSet.GetHttpInspectionRules()), 1; got != want {
		t.Fatalf("http inspection rules = %d, want %d", got, want)
	}
	rule := accessSet.GetHttpInspectionRules()[0]
	if !rule.GetDynamicHeaderAuthz() {
		t.Fatal("dynamic header authz = false, want true")
	}
}

func TestPresetProxyProjectsToExternalAccessSet(t *testing.T) {
	sets := PresetProxyAccessSets()
	if got, want := len(sets), 1; got != want {
		t.Fatalf("proxy access sets = %d, want %d", got, want)
	}
	accessSet := sets[0]
	if got, want := accessSet.GetAccessSetId(), "support.proxy-preset.preset-proxy"; got != want {
		t.Fatalf("access set id = %q, want %q", got, want)
	}
	if got, want := len(accessSet.GetExternalRules()), 0; got != want {
		t.Fatalf("external rules = %d, want %d", got, want)
	}
	if got, want := len(accessSet.GetProxyEndpoints()), 1; got != want {
		t.Fatalf("proxy endpoints = %d, want %d", got, want)
	}
	endpoint := accessSet.GetProxyEndpoints()[0]
	if got, want := endpoint.GetProxyEndpointId(), "preset-proxy"; got != want {
		t.Fatalf("proxy endpoint id = %q, want %q", got, want)
	}
	if got, want := endpoint.GetHostMatch().GetHostExact(), "preset-proxy.local"; got != want {
		t.Fatalf("host exact = %q, want %q", got, want)
	}
	if got, want := endpoint.GetAddressCidr(), "10.42.0.1/32"; got != want {
		t.Fatalf("address cidr = %q, want %q", got, want)
	}
	if got, want := endpoint.GetProtocol(), egressv1.ProxyProtocol_PROXY_PROTOCOL_HTTP_CONNECT; got != want {
		t.Fatalf("protocol = %v, want %v", got, want)
	}
	if got, want := endpoint.GetResolution(), egressv1.EgressResolution_EGRESS_RESOLUTION_NONE; got != want {
		t.Fatalf("resolution = %v, want %v", got, want)
	}
	if got, want := len(accessSet.GetServiceRules()), 0; got != want {
		t.Fatalf("service rules = %d, want %d", got, want)
	}
}

func TestStartupExternalAccessSetsIncludesOnlyNetworkOwnedSets(t *testing.T) {
	sets := StartupExternalAccessSets()
	if got, want := len(sets), 3; got != want {
		t.Fatalf("startup access sets = %d, want %d", got, want)
	}
	if got, want := sets[0].GetAccessSetId(), "support.proxy-preset.preset-proxy"; got != want {
		t.Fatalf("first access set id = %q, want %q", got, want)
	}
	if got, want := sets[1].GetAccessSetId(), "support.external-rule-set.bootstrap"; got != want {
		t.Fatalf("second access set id = %q, want %q", got, want)
	}
	if got, want := sets[2].GetAccessSetId(), "support.external-rule-set.model-catalog-sources"; got != want {
		t.Fatalf("third access set id = %q, want %q", got, want)
	}
}

func externalRuleByDestination(t *testing.T, accessSet *egressv1.ExternalAccessSet, destinationID string) *egressv1.ExternalRule {
	t.Helper()
	for _, rule := range accessSet.GetExternalRules() {
		if rule.GetDestinationId() == destinationID {
			return rule
		}
	}
	t.Fatalf("external rule destination %q not found", destinationID)
	return nil
}

func serviceRuleByDestination(t *testing.T, accessSet *egressv1.ExternalAccessSet, destinationID string) *egressv1.ServiceRule {
	t.Helper()
	for _, rule := range accessSet.GetServiceRules() {
		if rule.GetDestinationId() == destinationID {
			return rule
		}
	}
	t.Fatalf("service rule destination %q not found", destinationID)
	return nil
}
