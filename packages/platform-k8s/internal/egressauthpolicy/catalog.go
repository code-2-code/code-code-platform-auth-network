package egressauthpolicy

import (
	"embed"
	"fmt"
	"sort"
	"strings"
	"sync"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	"code-code.internal/platform-k8s/internal/egressauth"
	"sigs.k8s.io/yaml"
)

const (
	BearerExtensionProviderName  = "code-code-egress-auth-bearer"
	APIKeyExtensionProviderName  = "code-code-egress-auth-api-key"
	SessionExtensionProviderName = "code-code-egress-auth-session"
)

//go:embed policies.yaml
var policyFS embed.FS

type Catalog struct {
	policies map[string]policyConfig
}

var (
	defaultCatalogOnce sync.Once
	defaultCatalog     *Catalog
	defaultCatalogErr  error
)

func DefaultCatalog() (*Catalog, error) {
	defaultCatalogOnce.Do(func() {
		defaultCatalog, defaultCatalogErr = LoadDefaultCatalog()
	})
	return defaultCatalog, defaultCatalogErr
}

type policyFile struct {
	Policies []policyConfig `json:"policies"`
}

type policyConfig struct {
	PolicyID              string                  `json:"policyId"`
	AdapterID             string                  `json:"adapterId"`
	ExtensionProviderName string                  `json:"extensionProviderName"`
	Materializations      []materializationConfig `json:"materializations"`
}

type materializationConfig struct {
	MaterializationKey       string                             `json:"materializationKey"`
	RequestReplacementRules  []egressauth.SimpleReplacementRule `json:"requestReplacementRules"`
	ResponseReplacementRules []egressauth.SimpleReplacementRule `json:"responseReplacementRules"`
	HeaderValuePrefix        string                             `json:"headerValuePrefix"`
}

func LoadDefaultCatalog() (*Catalog, error) {
	raw, err := policyFS.ReadFile("policies.yaml")
	if err != nil {
		return nil, err
	}
	return LoadCatalog(raw)
}

func LoadCatalog(raw []byte) (*Catalog, error) {
	var file policyFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse egress auth policies: %w", err)
	}
	catalog := &Catalog{policies: map[string]policyConfig{}}
	for _, policy := range file.Policies {
		policy.PolicyID = strings.TrimSpace(policy.PolicyID)
		if policy.PolicyID == "" {
			return nil, fmt.Errorf("egress auth policy id is empty")
		}
		catalog.policies[policy.PolicyID] = policy
	}
	return catalog, nil
}

func (c *Catalog) Resolve(request *authv1.GetEgressAuthPolicyRequest) *authv1.GetEgressAuthPolicyResponse {
	policyID := strings.TrimSpace(request.GetPolicyId())
	materializationKey := strings.TrimSpace(request.GetMaterializationKey())
	if policyID == "" {
		policyID = fallbackPolicyID(request.GetCredentialKind(), request.GetProtocol().String())
	}
	policy, ok := c.policy(policyID)
	if !ok {
		policy = fallbackPolicy(policyID, request.GetCredentialKind(), request.GetProtocol().String())
	}
	return resolvePolicy(policy, materializationKey)
}

func (c *Catalog) ResolvePolicyID(policyID string) (*authv1.GetEgressAuthPolicyResponse, bool) {
	policy, ok := c.policy(policyID)
	if !ok {
		return nil, false
	}
	return resolvePolicy(policy, ""), true
}

func (c *Catalog) policy(policyID string) (policyConfig, bool) {
	if c == nil {
		return policyConfig{}, false
	}
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return policyConfig{}, false
	}
	policy, ok := c.policies[policyID]
	return policy, ok
}

func resolvePolicy(policy policyConfig, materializationKey string) *authv1.GetEgressAuthPolicyResponse {
	materialization := selectMaterialization(policy, materializationKey)
	requestRules := normalizeRules(materialization.RequestReplacementRules)
	responseRules := normalizeRules(materialization.ResponseReplacementRules)
	requestNames := ruleHeaderNames(requestRules)
	responseNames := ruleHeaderNames(responseRules)
	providerName := extensionProviderName(policy.ExtensionProviderName, requestNames, responseNames)
	return &authv1.GetEgressAuthPolicyResponse{
		PolicyId:                   strings.TrimSpace(policy.PolicyID),
		MaterializationKey:         firstNonEmpty(materialization.MaterializationKey, materializationKey),
		AdapterId:                  strings.TrimSpace(policy.AdapterID),
		RequestReplacementRules:    requestRules,
		ResponseReplacementRules:   responseRules,
		RequestHeaderNames:         requestNames,
		ResponseHeaderNames:        responseNames,
		HeaderValuePrefix:          strings.TrimSpace(materialization.HeaderValuePrefix),
		ExtensionProviderName:      providerName,
		HeadersToUpstreamOnAllow:   requestNames,
		HeadersToDownstreamOnAllow: responseNames,
		HeadersToDownstreamOnDeny:  downstreamDenyHeaders(responseNames),
	}
}

func selectMaterialization(policy policyConfig, materializationKey string) materializationConfig {
	materializationKey = strings.TrimSpace(materializationKey)
	for _, item := range policy.Materializations {
		if strings.TrimSpace(item.MaterializationKey) == materializationKey {
			return item
		}
	}
	if len(policy.Materializations) > 0 {
		return policy.Materializations[0]
	}
	return materializationConfig{MaterializationKey: materializationKey}
}

func normalizeRules(rules []egressauth.SimpleReplacementRule) []*authv1.EgressSimpleReplacementRule {
	out := make([]*authv1.EgressSimpleReplacementRule, 0, len(rules))
	for _, rule := range rules {
		normalized := normalizeRule(rule)
		if strings.TrimSpace(normalized.HeaderName) == "" {
			continue
		}
		out = append(out, normalized)
	}
	return out
}

func normalizeRule(rule egressauth.SimpleReplacementRule) *authv1.EgressSimpleReplacementRule {
	normalized := egressauth.NormalizeSimpleReplacementRule(rule)
	return &authv1.EgressSimpleReplacementRule{
		Mode:              normalized.Mode,
		HeaderName:        normalized.HeaderName,
		MaterialKey:       normalized.MaterialKey,
		HeaderValuePrefix: normalized.HeaderValuePrefix,
		Template:          normalized.Template,
	}
}

func ruleHeaderNames(rules []*authv1.EgressSimpleReplacementRule) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		name := strings.ToLower(strings.TrimSpace(rule.GetHeaderName()))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func extensionProviderName(explicit string, requestNames []string, responseNames []string) string {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		return explicit
	}
	if hasHeader(responseNames, egressauth.HTTPHeaderSetCookie) || hasHeader(requestNames, egressauth.HTTPHeaderCookie) {
		return SessionExtensionProviderName
	}
	if hasHeader(requestNames, egressauth.HTTPHeaderXAPIKey) || hasHeader(requestNames, egressauth.HTTPHeaderXGoogAPIKey) {
		return APIKeyExtensionProviderName
	}
	return BearerExtensionProviderName
}

func downstreamDenyHeaders(responseNames []string) []string {
	if len(responseNames) == 0 {
		return nil
	}
	values := append([]string{egressauth.HTTPHeaderContentType}, responseNames...)
	return sortedUniqueHeaders(values)
}

func sortedUniqueHeaders(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func hasHeader(values []string, header string) bool {
	header = strings.ToLower(strings.TrimSpace(header))
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == header {
			return true
		}
	}
	return false
}

func fallbackPolicy(policyID string, kind credentialv1.CredentialKind, protocol string) policyConfig {
	mode := egressauth.SimpleReplacementModeBearer
	header := egressauth.HTTPHeaderAuthorization
	key := egressauth.MaterialKeyAPIKey
	prefix := "Bearer"
	if kind == credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH {
		key = egressauth.MaterialKeyAccessToken
	}
	switch {
	case strings.Contains(strings.ToLower(protocol), "anthropic"):
		mode = egressauth.SimpleReplacementModeXAPIKey
		header = egressauth.HTTPHeaderXAPIKey
		prefix = ""
	case strings.Contains(strings.ToLower(protocol), "gemini"):
		mode = egressauth.SimpleReplacementModeGoogleAPIKey
		header = egressauth.HTTPHeaderXGoogAPIKey
		prefix = ""
	}
	return policyConfig{
		PolicyID: strings.TrimSpace(policyID),
		Materializations: []materializationConfig{{
			RequestReplacementRules: []egressauth.SimpleReplacementRule{{
				Mode:              mode,
				HeaderName:        header,
				MaterialKey:       key,
				HeaderValuePrefix: prefix,
			}},
		}},
	}
}

func fallbackPolicyID(kind credentialv1.CredentialKind, protocol string) string {
	suffix := ".api-key"
	if kind == credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH {
		suffix = ".oauth"
	}
	protocol = strings.ToLower(strings.TrimPrefix(protocol, "PROTOCOL_"))
	protocol = strings.ReplaceAll(protocol, "_", "-")
	if protocol == "" || protocol == "unspecified" {
		protocol = "default"
	}
	return "protocol." + protocol + suffix
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
