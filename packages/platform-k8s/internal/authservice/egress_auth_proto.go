package authservice

import (
	"sort"
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	"code-code.internal/platform-k8s/internal/egressauth"
)

func protoSimpleReplacementRules(rules []*authv1.EgressSimpleReplacementRule) []egressauth.SimpleReplacementRule {
	out := make([]egressauth.SimpleReplacementRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		out = append(out, egressauth.SimpleReplacementRule{
			Mode:              rule.GetMode(),
			HeaderName:        rule.GetHeaderName(),
			MaterialKey:       rule.GetMaterialKey(),
			HeaderValuePrefix: rule.GetHeaderValuePrefix(),
			Template:          rule.GetTemplate(),
		})
	}
	return out
}

func runtimeHeaderReplacementRulesToProto(rules []*managementv1.AgentRunRuntimeHeaderReplacementRule) []*authv1.EgressSimpleReplacementRule {
	out := make([]*authv1.EgressSimpleReplacementRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		out = append(out, &authv1.EgressSimpleReplacementRule{
			Mode:              rule.GetMode(),
			HeaderName:        rule.GetHeaderName(),
			MaterialKey:       rule.GetMaterialKey(),
			HeaderValuePrefix: rule.GetHeaderValuePrefix(),
			Template:          rule.GetTemplate(),
		})
	}
	return out
}

func runtimeHeaderReplacementRuleNames(rules []*managementv1.AgentRunRuntimeHeaderReplacementRule) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		name := normalizeHTTPHeaderName(rule.GetHeaderName())
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

func requestHeaderMutationsFromMap(headers map[string]string) []*authv1.EgressHeaderMutation {
	if len(headers) == 0 {
		return nil
	}
	normalized := make(map[string]string, len(headers))
	for name, value := range headers {
		name = normalizeHTTPHeaderName(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			continue
		}
		normalized[name] = value
	}
	names := make([]string, 0, len(normalized))
	for name := range normalized {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]*authv1.EgressHeaderMutation, 0, len(names))
	for _, name := range names {
		out = append(out, requestHeaderMutation(name, normalized[name]))
	}
	return out
}

func requestHeaderMutation(name string, value string) *authv1.EgressHeaderMutation {
	return egressHeaderMutation(name, value, authv1.EgressHeaderAppendAction_EGRESS_HEADER_APPEND_ACTION_OVERWRITE_IF_EXISTS_OR_ADD)
}

func responseHeaderMutation(name string, value string) *authv1.EgressHeaderMutation {
	action := authv1.EgressHeaderAppendAction_EGRESS_HEADER_APPEND_ACTION_OVERWRITE_IF_EXISTS_OR_ADD
	if normalizeHTTPHeaderName(name) == egressauth.HTTPHeaderSetCookie {
		action = authv1.EgressHeaderAppendAction_EGRESS_HEADER_APPEND_ACTION_APPEND_IF_EXISTS_OR_ADD
	}
	return egressHeaderMutation(name, value, action)
}

func egressHeaderMutation(name string, value string, action authv1.EgressHeaderAppendAction) *authv1.EgressHeaderMutation {
	name = normalizeHTTPHeaderName(name)
	value = strings.TrimSpace(value)
	if name == "" || value == "" {
		return nil
	}
	return &authv1.EgressHeaderMutation{
		Name:         name,
		Value:        value,
		AppendAction: action,
	}
}

func headerMutationNames(headers []*authv1.EgressHeaderMutation) []string {
	if len(headers) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(headers))
	for _, header := range headers {
		if header == nil {
			continue
		}
		name := normalizeHTTPHeaderName(header.GetName())
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

func materialFromResolvedCredential(credential *credentialv1.ResolvedCredential) map[string]string {
	if credential == nil {
		return nil
	}
	material := map[string]string{}
	if apiKey := credential.GetApiKey(); apiKey != nil {
		setResolvedMaterial(material, egressauth.MaterialKeyAPIKey, apiKey.GetApiKey())
	}
	if oauth := credential.GetOauth(); oauth != nil {
		setResolvedMaterial(material, egressauth.MaterialKeyAccessToken, oauth.GetAccessToken())
		setResolvedMaterial(material, "token", oauth.GetAccessToken())
		setResolvedMaterial(material, "token_type", oauth.GetTokenType())
		setResolvedMaterial(material, "refresh_token", oauth.GetRefreshToken())
		setResolvedMaterial(material, "id_token", oauth.GetIdToken())
	}
	if session := credential.GetSession(); session != nil {
		for key, value := range session.GetValues() {
			setResolvedMaterial(material, key, value)
		}
	}
	if len(material) == 0 {
		return nil
	}
	return material
}

func setResolvedMaterial(material map[string]string, key string, value string) {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return
	}
	material[key] = value
}

func headerReplacementItemsFromMap(headers map[string]string, names []string) []*authv1.EgressHeaderReplacementItem {
	if len(headers) == 0 {
		return nil
	}
	allowed := headerNameSet(names)
	items := make([]*authv1.EgressHeaderReplacementItem, 0, len(headers))
	for name, value := range headers {
		name = normalizeHTTPHeaderName(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[name]; !ok {
				continue
			}
		}
		items = append(items, &authv1.EgressHeaderReplacementItem{Name: name, CurrentValue: value})
	}
	return items
}
