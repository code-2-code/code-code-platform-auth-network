package egressauth

import (
	"strings"
	"time"
)

type ReplacementInput struct {
	AdapterID         string
	HeaderName        string
	HeaderValuePrefix string
	CurrentValue      string
	Origin            string
	RequestHeaders    map[string]string
	Material          map[string]string
	Now               time.Time
}

type SimpleReplacementRule struct {
	Mode              string `json:"mode,omitempty"`
	HeaderName        string `json:"headerName,omitempty"`
	MaterialKey       string `json:"materialKey,omitempty"`
	HeaderValuePrefix string `json:"headerValuePrefix,omitempty"`
	Template          string `json:"template,omitempty"`
}

const (
	SimpleReplacementModeBearer       = "bearer"
	SimpleReplacementModeAPIKey       = "api-key"
	SimpleReplacementModeCookie       = "cookie"
	SimpleReplacementModeGoogleAPIKey = "google-api-key"
	SimpleReplacementModeXAPIKey      = "x-api-key"
)

func ReplaceSimpleHeader(input ReplacementInput, rules ...SimpleReplacementRule) (string, bool) {
	headerName := strings.ToLower(strings.TrimSpace(input.HeaderName))
	current := strings.TrimSpace(input.CurrentValue)
	if headerName == "" || !strings.Contains(current, Placeholder) || !hasReplacementMaterial(input.Material) {
		return "", false
	}
	if rule, ok := simpleRuleForHeader(rules, headerName); ok {
		return replaceRuleHeader(input, rule, headerName, current)
	}
	return "", false
}

func replaceRuleHeader(input ReplacementInput, rule SimpleReplacementRule, headerName string, current string) (string, bool) {
	rule = NormalizeSimpleReplacementRule(rule)
	if rule.Mode == SimpleReplacementModeCookie && normalizeMaterialKey(headerName) == MaterialKeyCookie && strings.TrimSpace(rule.MaterialKey) == "" && strings.TrimSpace(rule.Template) == "" {
		return cookieReplacement(input.Material, current)
	}
	token := ""
	if key := strings.TrimSpace(rule.MaterialKey); key != "" {
		token = materialByKey(input.Material, key)
	}
	if template := strings.TrimSpace(rule.Template); template != "" {
		if token == "" || !strings.Contains(template, Placeholder) {
			return "", false
		}
		return strings.ReplaceAll(template, Placeholder, token), true
	}
	prefix := firstNonEmpty(rule.HeaderValuePrefix, input.HeaderValuePrefix)
	if strings.TrimSpace(current) == Placeholder && strings.TrimSpace(prefix) != "" {
		if token == "" {
			return "", false
		}
		return strings.TrimSpace(prefix) + " " + token, true
	}
	return replacementValue(current, prefix, token)
}

func simpleRuleForHeader(rules []SimpleReplacementRule, headerName string) (SimpleReplacementRule, bool) {
	headerName = strings.ToLower(strings.TrimSpace(headerName))
	for _, rule := range rules {
		normalized := NormalizeSimpleReplacementRule(rule)
		if strings.ToLower(strings.TrimSpace(normalized.HeaderName)) == headerName {
			return normalized, true
		}
	}
	return SimpleReplacementRule{}, false
}

func NormalizeSimpleReplacementRule(rule SimpleReplacementRule) SimpleReplacementRule {
	rule.Mode = strings.ToLower(strings.TrimSpace(rule.Mode))
	rule.HeaderName = strings.ToLower(strings.TrimSpace(rule.HeaderName))
	rule.MaterialKey = strings.TrimSpace(rule.MaterialKey)
	rule.HeaderValuePrefix = strings.TrimSpace(rule.HeaderValuePrefix)
	rule.Template = strings.TrimSpace(rule.Template)
	switch rule.Mode {
	case SimpleReplacementModeBearer:
		if rule.MaterialKey == "" {
			rule.MaterialKey = MaterialKeyAccessToken
		}
		if rule.HeaderValuePrefix == "" && rule.Template == "" {
			rule.HeaderValuePrefix = "Bearer"
		}
	case SimpleReplacementModeCookie:
	case SimpleReplacementModeGoogleAPIKey:
		if rule.MaterialKey == "" {
			rule.MaterialKey = MaterialKeyAPIKey
		}
	case SimpleReplacementModeXAPIKey:
		if rule.MaterialKey == "" {
			rule.MaterialKey = MaterialKeyAPIKey
		}
	case SimpleReplacementModeAPIKey:
		if rule.MaterialKey == "" {
			rule.MaterialKey = MaterialKeyAPIKey
		}
	}
	return rule
}

func SimpleReplacementRuleHeaderNames(rules []SimpleReplacementRule) []string {
	out := make([]string, 0, len(rules))
	seen := map[string]struct{}{}
	for _, rule := range rules {
		name := strings.ToLower(strings.TrimSpace(rule.HeaderName))
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

func replacementValue(current string, prefix string, token string) (string, bool) {
	if token == "" {
		return "", false
	}
	current = strings.TrimSpace(current)
	if current == Placeholder {
		return token, true
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		if strings.Contains(current, Placeholder) {
			return strings.ReplaceAll(current, Placeholder, token), true
		}
		return "", false
	}
	if current == prefix+" "+Placeholder {
		return prefix + " " + token, true
	}
	if strings.Contains(current, Placeholder) {
		return strings.ReplaceAll(current, Placeholder, token), true
	}
	return "", false
}

func hasReplacementMaterial(material map[string]string) bool {
	return firstNonEmptyMaterial(material) != ""
}

func firstNonEmptyMaterial(material map[string]string) string {
	for _, value := range material {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func materialByKey(material map[string]string, key string) string {
	key = normalizeMaterialKey(key)
	for currentKey, value := range material {
		if normalizeMaterialKey(currentKey) == key {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func normalizeMaterialKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("-", "_", ".", "_")
	return replacer.Replace(value)
}

func cookieReplacement(material map[string]string, current string) (string, bool) {
	current = strings.TrimSpace(current)
	if current == "" || !strings.Contains(current, Placeholder) {
		return "", false
	}
	if current == Placeholder {
		if cookie := cookieHeaderMaterial(material); cookie != "" {
			return cookie, true
		}
		return "", false
	}
	parts := strings.Split(current, ";")
	replaced := false
	for index, part := range parts {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.Contains(value, Placeholder) {
			continue
		}
		materialValue := cookiePairMaterial(material, key)
		if materialValue == "" {
			continue
		}
		parts[index] = strings.TrimSpace(key) + "=" + strings.ReplaceAll(value, Placeholder, materialValue)
		replaced = true
	}
	if !replaced {
		return "", false
	}
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			cleaned = append(cleaned, part)
		}
	}
	return strings.Join(cleaned, "; "), true
}

func cookieHeaderMaterial(material map[string]string) string {
	return materialByKey(material, MaterialKeyCookie)
}

func cookiePairMaterial(material map[string]string, name string) string {
	if value := cookieValue(cookieHeaderMaterial(material), name); value != "" {
		return value
	}
	if value := materialByKey(material, name); value != "" {
		return value
	}
	if strings.HasPrefix(name, "__Secure-") {
		return materialByKey(material, strings.TrimPrefix(name, "__Secure-"))
	}
	return ""
}

func cookieValue(header string, name string) string {
	name = strings.TrimSpace(name)
	for key, value := range parseCookieHeader(header) {
		if key == name {
			return value
		}
	}
	return ""
}

func parseCookieHeader(header string) map[string]string {
	jar := map[string]string{}
	for _, part := range strings.Split(header, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			jar[key] = value
		}
	}
	return jar
}
