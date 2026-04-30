package support

import (
	"fmt"
	"slices"
	"strings"
)

func normalizeExternalRuleSetFile(file externalRuleSetFile) ([]externalRuleSetConfig, error) {
	seenSets := map[string]struct{}{}
	ruleSets := make([]externalRuleSetConfig, 0, len(file.RuleSets))
	for setIndex, ruleSet := range file.RuleSets {
		normalizedSet := externalRuleSetConfig{
			RuleSetID:             strings.TrimSpace(ruleSet.RuleSetID),
			DisplayName:           strings.TrimSpace(ruleSet.DisplayName),
			OwnerService:          strings.TrimSpace(ruleSet.OwnerService),
			PolicyID:              strings.TrimSpace(ruleSet.PolicyID),
			StartupSync:           boolPtr(startupSyncEnabled(ruleSet.StartupSync)),
			SourceServiceAccounts: normalizeStringList(ruleSet.SourceServiceAccounts),
			Rules:                 make([]externalRuleSetRule, 0, len(ruleSet.Rules)),
			HTTPInspectionRules:   make([]externalRuleSetHTTPInspectionRule, 0, len(ruleSet.HTTPInspectionRules)),
		}
		if normalizedSet.RuleSetID == "" {
			return nil, fmt.Errorf("ruleSets[%d].ruleSetId is required", setIndex)
		}
		if _, ok := seenSets[normalizedSet.RuleSetID]; ok {
			return nil, fmt.Errorf("duplicate ruleSetId %q", normalizedSet.RuleSetID)
		}
		seenSets[normalizedSet.RuleSetID] = struct{}{}
		if normalizedSet.DisplayName == "" {
			normalizedSet.DisplayName = normalizedSet.RuleSetID
		}
		if normalizedSet.OwnerService == "" {
			return nil, fmt.Errorf("ruleSet %q ownerService is required", normalizedSet.RuleSetID)
		}
		if len(normalizedSet.SourceServiceAccounts) == 0 {
			return nil, fmt.Errorf("ruleSet %q sourceServiceAccounts is required", normalizedSet.RuleSetID)
		}
		if len(ruleSet.Rules) == 0 {
			return nil, fmt.Errorf("ruleSet %q rules is required", normalizedSet.RuleSetID)
		}
		seenRules := map[string]struct{}{}
		for ruleIndex, rule := range ruleSet.Rules {
			normalizedRule, err := normalizeExternalRuleSetRule(normalizedSet.RuleSetID, ruleIndex, rule)
			if err != nil {
				return nil, fmt.Errorf("ruleSet %q: %w", normalizedSet.RuleSetID, err)
			}
			if _, ok := seenRules[normalizedRule.RuleID]; ok {
				return nil, fmt.Errorf("ruleSet %q duplicate ruleId %q", normalizedSet.RuleSetID, normalizedRule.RuleID)
			}
			seenRules[normalizedRule.RuleID] = struct{}{}
			normalizedSet.Rules = append(normalizedSet.Rules, normalizedRule)
		}
		slices.SortFunc(normalizedSet.Rules, func(left, right externalRuleSetRule) int {
			return strings.Compare(left.RuleID, right.RuleID)
		})
		knownDestinations := map[string]struct{}{}
		for _, rule := range normalizedSet.Rules {
			knownDestinations[rule.DestinationID] = struct{}{}
		}
		seenInspectionRules := map[string]struct{}{}
		for ruleIndex, rule := range ruleSet.HTTPInspectionRules {
			normalizedRule, err := normalizeExternalRuleSetHTTPInspectionRule(ruleIndex, rule, knownDestinations)
			if err != nil {
				return nil, fmt.Errorf("ruleSet %q: %w", normalizedSet.RuleSetID, err)
			}
			if _, ok := seenInspectionRules[normalizedRule.InspectionRuleID]; ok {
				return nil, fmt.Errorf("ruleSet %q duplicate http inspection rule %q", normalizedSet.RuleSetID, normalizedRule.InspectionRuleID)
			}
			seenInspectionRules[normalizedRule.InspectionRuleID] = struct{}{}
			normalizedSet.HTTPInspectionRules = append(normalizedSet.HTTPInspectionRules, normalizedRule)
		}
		slices.SortFunc(normalizedSet.HTTPInspectionRules, func(left, right externalRuleSetHTTPInspectionRule) int {
			return strings.Compare(left.InspectionRuleID, right.InspectionRuleID)
		})
		ruleSets = append(ruleSets, normalizedSet)
	}
	slices.SortFunc(ruleSets, func(left, right externalRuleSetConfig) int {
		return strings.Compare(left.RuleSetID, right.RuleSetID)
	})
	return ruleSets, nil
}

func normalizeExternalRuleSetRule(ruleSetID string, index int, rule externalRuleSetRule) (externalRuleSetRule, error) {
	ruleID := strings.TrimSpace(rule.RuleID)
	if ruleID == "" {
		return externalRuleSetRule{}, fmt.Errorf("rules[%d].ruleId is required", index)
	}
	hostExact := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.HostExact), "."))
	hostWildcard := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.HostWildcard), "."))
	if (hostExact == "") == (hostWildcard == "") {
		return externalRuleSetRule{}, fmt.Errorf("rule %q must set exactly one of hostExact or hostWildcard", ruleID)
	}
	destinationID := strings.TrimSpace(rule.DestinationID)
	if destinationID == "" {
		destinationID = ruleSetID + "." + ruleID
	}
	displayName := strings.TrimSpace(rule.DisplayName)
	if displayName == "" {
		displayName = ruleID
	}
	port := rule.Port
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return externalRuleSetRule{}, fmt.Errorf("rule %q port must be between 1 and 65535", ruleID)
	}
	return externalRuleSetRule{
		RuleID:                ruleID,
		DestinationID:         destinationID,
		DisplayName:           displayName,
		HostExact:             hostExact,
		HostWildcard:          hostWildcard,
		Port:                  port,
		Protocol:              strings.TrimSpace(rule.Protocol),
		Resolution:            strings.TrimSpace(rule.Resolution),
		SourceServiceAccounts: normalizeStringList(rule.SourceServiceAccounts),
		ProxyEndpointID:       strings.TrimSpace(rule.ProxyEndpointID),
	}, nil
}

func normalizeExternalRuleSetHTTPInspectionRule(index int, rule externalRuleSetHTTPInspectionRule, knownDestinations map[string]struct{}) (externalRuleSetHTTPInspectionRule, error) {
	inspectionRuleID := strings.TrimSpace(rule.InspectionRuleID)
	if inspectionRuleID == "" {
		return externalRuleSetHTTPInspectionRule{}, fmt.Errorf("httpInspectionRules[%d].inspectionRuleId is required", index)
	}
	destinationID := strings.TrimSpace(rule.DestinationID)
	if destinationID == "" {
		return externalRuleSetHTTPInspectionRule{}, fmt.Errorf("http inspection rule %q destinationId is required", inspectionRuleID)
	}
	if _, ok := knownDestinations[destinationID]; !ok {
		return externalRuleSetHTTPInspectionRule{}, fmt.Errorf("http inspection rule %q references unknown destination %q", inspectionRuleID, destinationID)
	}
	displayName := strings.TrimSpace(rule.DisplayName)
	if displayName == "" {
		displayName = inspectionRuleID
	}
	return externalRuleSetHTTPInspectionRule{
		InspectionRuleID:   inspectionRuleID,
		DisplayName:        displayName,
		DestinationID:      destinationID,
		Matches:            normalizeExternalRuleSetMatches(rule.Matches),
		RequestHeaders:     normalizeExternalRuleSetHeaderPolicy(rule.RequestHeaders),
		ResponseHeaders:    normalizeExternalRuleSetHeaderPolicy(rule.ResponseHeaders),
		AuthPolicyID:       strings.TrimSpace(rule.AuthPolicyID),
		DynamicHeaderAuthz: rule.DynamicHeaderAuthz,
	}, nil
}

func normalizeExternalRuleSetMatches(matches []externalRuleSetMatch) []externalRuleSetMatch {
	out := make([]externalRuleSetMatch, 0, len(matches))
	for _, match := range matches {
		out = append(out, externalRuleSetMatch{
			PathPrefixes: normalizeStringList(match.PathPrefixes),
			Methods:      normalizeStringList(match.Methods),
		})
	}
	return out
}

func normalizeExternalRuleSetHeaderPolicy(policy externalRuleSetHeaderPolicy) externalRuleSetHeaderPolicy {
	return externalRuleSetHeaderPolicy{
		Add:    normalizeExternalRuleSetHeaderValues(policy.Add),
		Set:    normalizeExternalRuleSetHeaderValues(policy.Set),
		Remove: normalizeStringList(policy.Remove),
	}
}

func normalizeExternalRuleSetHeaderValues(values []externalRuleSetHeaderValue) []externalRuleSetHeaderValue {
	out := make([]externalRuleSetHeaderValue, 0, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value.Name)
		if name == "" {
			continue
		}
		out = append(out, externalRuleSetHeaderValue{Name: name, Value: value.Value})
	}
	return out
}
