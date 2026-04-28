package egresspolicies

import (
	"embed"
	"fmt"
	"net/url"
	"slices"
	"strings"

	egressservicev1 "code-code.internal/go-contract/platform/egress/v1"
	"sigs.k8s.io/yaml"
)

//go:embed runtime_policies.yaml
var runtimePolicyFS embed.FS

type runtimePolicyCatalog struct {
	policies map[string]runtimePolicyConfig
}

type runtimePolicyFile struct {
	Policies []runtimePolicyConfig `json:"policies"`
}

type runtimePolicyConfig struct {
	PolicyID              string   `json:"policyId"`
	IncludeRuntimeURLHost bool     `json:"includeRuntimeUrlHost"`
	ExtraTargetHosts      []string `json:"extraTargetHosts"`
	TargetPathPrefixes    []string `json:"targetPathPrefixes"`
}

func loadRuntimePolicyCatalog() (*runtimePolicyCatalog, error) {
	raw, err := runtimePolicyFS.ReadFile("runtime_policies.yaml")
	if err != nil {
		return nil, err
	}
	var file runtimePolicyFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse egress runtime policies: %w", err)
	}
	catalog := &runtimePolicyCatalog{policies: map[string]runtimePolicyConfig{}}
	for _, policy := range file.Policies {
		policy.PolicyID = strings.TrimSpace(policy.PolicyID)
		if policy.PolicyID == "" {
			return nil, fmt.Errorf("egress runtime policy id is empty")
		}
		catalog.policies[policy.PolicyID] = policy
	}
	return catalog, nil
}

func (c *runtimePolicyCatalog) resolve(policyID string, runtimeURL string) (*egressservicev1.EgressRuntimePolicy, error) {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, fmt.Errorf("egress runtime policy id is empty")
	}
	config, ok := c.policies[policyID]
	if !ok {
		config = runtimePolicyConfig{
			PolicyID:              policyID,
			IncludeRuntimeURLHost: true,
			TargetPathPrefixes:    []string{"/"},
		}
	}
	hosts := make([]string, 0, len(config.ExtraTargetHosts)+1)
	if config.IncludeRuntimeURLHost {
		if host := hostFromRuntimeURL(runtimeURL); host != "" {
			hosts = append(hosts, host)
		}
	}
	hosts = append(hosts, config.ExtraTargetHosts...)
	hosts = dedupeStrings(hosts)
	paths := dedupeStrings(config.TargetPathPrefixes)
	if len(paths) == 0 {
		paths = []string{"/"}
	}
	return &egressservicev1.EgressRuntimePolicy{
		PolicyId:           policyID,
		TargetHosts:        hosts,
		TargetPathPrefixes: paths,
	}, nil
}

func hostFromRuntimeURL(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return normalizeRuntimePolicyHost(value)
	}
	return normalizeRuntimePolicyHost(parsed.Host)
}

func normalizeRuntimePolicyHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	if index := strings.IndexAny(value, "/?#"); index >= 0 {
		value = value[:index]
	}
	if index := strings.LastIndex(value, ":"); index > 0 && !strings.Contains(value[:index], ":") {
		value = value[:index]
	}
	return strings.Trim(value, "[]")
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}
