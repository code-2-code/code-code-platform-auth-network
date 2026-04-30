package support

import (
	"bytes"
	"embed"
	"fmt"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
	"gopkg.in/yaml.v3"
)

//go:embed external_rule_sets.yaml
var externalRuleSetFS embed.FS

type externalRuleSetFile struct {
	RuleSets []externalRuleSetConfig `yaml:"ruleSets"`
}

type externalRuleSetConfig struct {
	RuleSetID             string                              `yaml:"ruleSetId"`
	DisplayName           string                              `yaml:"displayName"`
	OwnerService          string                              `yaml:"ownerService"`
	PolicyID              string                              `yaml:"policyId"`
	StartupSync           *bool                               `yaml:"startupSync"`
	SourceServiceAccounts []string                            `yaml:"sourceServiceAccounts"`
	Rules                 []externalRuleSetRule               `yaml:"rules"`
	HTTPInspectionRules   []externalRuleSetHTTPInspectionRule `yaml:"httpInspectionRules"`
}

type externalRuleSetRule struct {
	RuleID                string   `yaml:"ruleId"`
	DestinationID         string   `yaml:"destinationId"`
	DisplayName           string   `yaml:"displayName"`
	HostExact             string   `yaml:"hostExact"`
	HostWildcard          string   `yaml:"hostWildcard"`
	Port                  int32    `yaml:"port"`
	Protocol              string   `yaml:"protocol"`
	Resolution            string   `yaml:"resolution"`
	SourceServiceAccounts []string `yaml:"sourceServiceAccounts"`
	ProxyEndpointID       string   `yaml:"proxyEndpointId"`
}

type externalRuleSetHTTPInspectionRule struct {
	InspectionRuleID   string                      `yaml:"inspectionRuleId"`
	DisplayName        string                      `yaml:"displayName"`
	DestinationID      string                      `yaml:"destinationId"`
	Matches            []externalRuleSetMatch      `yaml:"matches"`
	RequestHeaders     externalRuleSetHeaderPolicy `yaml:"requestHeaders"`
	ResponseHeaders    externalRuleSetHeaderPolicy `yaml:"responseHeaders"`
	AuthPolicyID       string                      `yaml:"authPolicyId"`
	DynamicHeaderAuthz bool                        `yaml:"dynamicHeaderAuthz"`
}

type externalRuleSetMatch struct {
	PathPrefixes []string `yaml:"pathPrefixes"`
	Methods      []string `yaml:"methods"`
}

type externalRuleSetHeaderPolicy struct {
	Add    []externalRuleSetHeaderValue `yaml:"add"`
	Set    []externalRuleSetHeaderValue `yaml:"set"`
	Remove []string                     `yaml:"remove"`
}

type externalRuleSetHeaderValue struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

var presetExternalRuleSets = mustLoadExternalRuleSets()

func StartupExternalAccessSets() []*egressv1.ExternalAccessSet {
	sets := PresetProxyAccessSets()
	sets = append(sets, PresetExternalRuleSetAccessSets()...)
	return sets
}

func PresetExternalRuleSetAccessSets() []*egressv1.ExternalAccessSet {
	out := make([]*egressv1.ExternalAccessSet, 0, len(presetExternalRuleSets))
	for _, ruleSet := range presetExternalRuleSets {
		if !startupSyncEnabled(ruleSet.StartupSync) {
			continue
		}
		out = append(out, externalAccessSetFromRuleSet(ruleSet))
	}
	return out
}

func ExternalRuleSetAccessSet(ruleSetID string) (*egressv1.ExternalAccessSet, bool) {
	ruleSetID = strings.TrimSpace(ruleSetID)
	for _, ruleSet := range presetExternalRuleSets {
		if ruleSet.RuleSetID == ruleSetID {
			return externalAccessSetFromRuleSet(ruleSet), true
		}
	}
	return nil, false
}

func mustLoadExternalRuleSets() []externalRuleSetConfig {
	payload, err := externalRuleSetFS.ReadFile("external_rule_sets.yaml")
	if err != nil {
		panic(fmt.Sprintf("platformk8s/vendors/support: read external rule sets: %v", err))
	}
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
	var file externalRuleSetFile
	if err := decoder.Decode(&file); err != nil {
		panic(fmt.Sprintf("platformk8s/vendors/support: parse external rule sets: %v", err))
	}
	ruleSets, err := normalizeExternalRuleSetFile(file)
	if err != nil {
		panic(fmt.Sprintf("platformk8s/vendors/support: invalid external rule sets: %v", err))
	}
	return ruleSets
}

func startupSyncEnabled(value *bool) bool {
	return value == nil || *value
}

func boolPtr(value bool) *bool {
	return &value
}
