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
	Source                policySourceConfig      `json:"source"`
	Target                policyTargetConfig      `json:"target"`
	Materializations      []materializationConfig `json:"materializations"`
}

type policySourceConfig struct {
	Principals      []string `json:"principals"`
	ServiceAccounts []string `json:"serviceAccounts"`
}

type policyTargetConfig struct {
	Hosts        []string `json:"hosts"`
	PathPrefixes []string `json:"pathPrefixes"`
	Methods      []string `json:"methods"`
}

type materializationConfig struct {
	MaterializationKey       string                             `json:"materializationKey"`
	CredentialID             string                             `json:"credentialId"`
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

func (c *Catalog) ResolveRequestPolicy(request *authv1.ResolveEgressRequestHeadersRequest) (*authv1.GetEgressAuthPolicyResponse, bool, error) {
	if c == nil || request == nil {
		return nil, false, nil
	}
	matches := make([]policyConfig, 0, 1)
	for _, policy := range c.policies {
		if !policyHasRequestMatch(policy) {
			continue
		}
		if !policyMatchesRequest(policy, request.GetSourcePrincipal(), request.GetTargetHost(), request.GetTargetPath(), request.GetTargetMethod()) {
			continue
		}
		matches = append(matches, policy)
	}
	if len(matches) == 0 {
		return nil, false, nil
	}
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for _, match := range matches {
			ids = append(ids, strings.TrimSpace(match.PolicyID))
		}
		sort.Strings(ids)
		return nil, false, fmt.Errorf("multiple egress auth policies match request: %s", strings.Join(ids, ", "))
	}
	return resolvePolicy(matches[0], ""), true, nil
}

func (c *Catalog) ResolveResponsePolicy(request *authv1.ResolveEgressResponseHeadersRequest) (*authv1.GetEgressAuthPolicyResponse, bool, error) {
	if c == nil || request == nil {
		return nil, false, nil
	}
	matches := make([]policyConfig, 0, 1)
	for _, policy := range c.policies {
		if !policyHasResponseMatch(policy) {
			continue
		}
		if !policyMatchesRequest(policy, request.GetSourcePrincipal(), request.GetTargetHost(), request.GetTargetPath(), request.GetTargetMethod()) {
			continue
		}
		matches = append(matches, policy)
	}
	if len(matches) == 0 {
		return nil, false, nil
	}
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for _, match := range matches {
			ids = append(ids, strings.TrimSpace(match.PolicyID))
		}
		sort.Strings(ids)
		return nil, false, fmt.Errorf("multiple egress auth policies match response: %s", strings.Join(ids, ", "))
	}
	return resolvePolicy(matches[0], ""), true, nil
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
		CredentialId:               strings.TrimSpace(materialization.CredentialID),
		Source: &authv1.EgressAuthPolicySource{
			Principals:      normalizedStrings(policy.Source.Principals),
			ServiceAccounts: normalizedStrings(policy.Source.ServiceAccounts),
		},
		Target: &authv1.EgressAuthPolicyTarget{
			Hosts:        normalizedHosts(policy.Target.Hosts),
			PathPrefixes: normalizedStrings(policy.Target.PathPrefixes),
			Methods:      normalizedMethods(policy.Target.Methods),
		},
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

func policyHasRequestMatch(policy policyConfig) bool {
	if !policyHasMatch(policy) {
		return false
	}
	for _, materialization := range policy.Materializations {
		if len(normalizeRules(materialization.RequestReplacementRules)) > 0 {
			return true
		}
	}
	return false
}

func policyHasResponseMatch(policy policyConfig) bool {
	if !policyHasMatch(policy) {
		return false
	}
	for _, materialization := range policy.Materializations {
		if len(normalizeRules(materialization.ResponseReplacementRules)) > 0 {
			return true
		}
	}
	return false
}

func policyHasMatch(policy policyConfig) bool {
	return len(normalizedStrings(policy.Source.Principals)) > 0 ||
		len(normalizedStrings(policy.Source.ServiceAccounts)) > 0 ||
		len(normalizedHosts(policy.Target.Hosts)) > 0 ||
		len(normalizedStrings(policy.Target.PathPrefixes)) > 0 ||
		len(normalizedMethods(policy.Target.Methods)) > 0
}

func policyMatchesRequest(policy policyConfig, sourcePrincipal string, targetHost string, targetPath string, method string) bool {
	return sourceMatches(policy.Source, sourcePrincipal) &&
		targetMatches(policy.Target, targetHost, targetPath, method)
}

func sourceMatches(source policySourceConfig, sourcePrincipal string) bool {
	principals := normalizedPrincipals(source.Principals)
	serviceAccounts := normalizedStrings(source.ServiceAccounts)
	if len(principals) == 0 && len(serviceAccounts) == 0 {
		return true
	}
	principal := normalizePrincipal(sourcePrincipal)
	if principal == "" {
		return false
	}
	if len(principals) > 0 {
		for _, allowed := range principals {
			if allowed == principal {
				return true
			}
		}
	}
	if len(serviceAccounts) > 0 {
		account := serviceAccountFromPrincipal(principal)
		for _, allowed := range serviceAccounts {
			if allowed == account {
				return true
			}
		}
	}
	return false
}

func targetMatches(target policyTargetConfig, targetHost string, targetPath string, method string) bool {
	return hostMatches(target.Hosts, targetHost) &&
		pathMatches(target.PathPrefixes, targetPath) &&
		methodMatches(target.Methods, method)
}

func hostMatches(allowedHosts []string, targetHost string) bool {
	hosts := normalizedHosts(allowedHosts)
	if len(hosts) == 0 {
		return true
	}
	targetHost = normalizeHost(targetHost)
	if targetHost == "" {
		return false
	}
	for _, allowed := range hosts {
		if allowed == targetHost {
			return true
		}
		if strings.HasPrefix(allowed, "*.") && strings.HasSuffix(targetHost, strings.TrimPrefix(allowed, "*")) {
			return true
		}
	}
	return false
}

func pathMatches(prefixes []string, targetPath string) bool {
	prefixes = normalizedStrings(prefixes)
	if len(prefixes) == 0 {
		return true
	}
	targetPath = strings.TrimSpace(targetPath)
	if targetPath == "" {
		targetPath = "/"
	}
	for _, prefix := range prefixes {
		if prefix == "/" || strings.HasPrefix(targetPath, prefix) {
			return true
		}
	}
	return false
}

func methodMatches(methods []string, method string) bool {
	methods = normalizedMethods(methods)
	if len(methods) == 0 {
		return true
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, allowed := range methods {
		if allowed == method {
			return true
		}
	}
	return false
}

func normalizedStrings(values []string) []string {
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
	sort.Strings(out)
	return out
}

func normalizedMethods(values []string) []string {
	out := normalizedStrings(values)
	for index, value := range out {
		out[index] = strings.ToUpper(value)
	}
	sort.Strings(out)
	return out
}

func normalizedHosts(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if host := normalizeHost(value); host != "" {
			out = append(out, host)
		}
	}
	return sortedUniqueHeaders(out)
}

func normalizedPrincipals(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if principal := normalizePrincipal(value); principal != "" {
			out = append(out, principal)
		}
	}
	return sortedUniqueHeaders(out)
}

func normalizeHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	if index := strings.Index(value, "/"); index >= 0 {
		value = value[:index]
	}
	if index := strings.LastIndex(value, ":"); index > 0 && !strings.Contains(value[:index], ":") {
		value = value[:index]
	}
	return strings.Trim(value, "[]")
}

func normalizePrincipal(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "spiffe://")
	return value
}

func serviceAccountFromPrincipal(principal string) string {
	parts := strings.Split(normalizePrincipal(principal), "/")
	for index := 0; index+3 < len(parts); index++ {
		if parts[index] == "ns" && parts[index+2] == "sa" {
			namespace := strings.TrimSpace(parts[index+1])
			serviceAccount := strings.TrimSpace(parts[index+3])
			if namespace != "" && serviceAccount != "" {
				return namespace + "/" + serviceAccount
			}
		}
	}
	return ""
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
