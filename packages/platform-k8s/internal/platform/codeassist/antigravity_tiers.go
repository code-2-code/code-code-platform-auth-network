package codeassist

import "strings"

func antigravityDefaultTierID(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	tiers, _ := payload["allowedTiers"].([]any)
	for _, raw := range tiers {
		tier, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		isDefault, _ := tier["isDefault"].(bool)
		if !isDefault {
			continue
		}
		id, _ := tier["id"].(string)
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func antigravityShouldOnboard(payload map[string]any) bool {
	if payload == nil {
		return false
	}
	return payload["currentTier"] == nil
}

func antigravityTierIDFromCodeAssistResponse(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	if id := antigravityTierID(payload["paidTier"]); id != "" {
		return id
	}
	ineligible := antigravityHasIneligibleTiers(payload["ineligibleTiers"])
	if !ineligible {
		if id := antigravityTierID(payload["currentTier"]); id != "" {
			return id
		}
	}
	return antigravityDefaultAllowedTierID(payload["allowedTiers"])
}

func antigravityTierNameFromCodeAssistResponse(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	if name := antigravityTierLabel(payload["paidTier"]); name != "" {
		return name
	}
	ineligible := antigravityHasIneligibleTiers(payload["ineligibleTiers"])
	if !ineligible {
		if name := antigravityTierLabel(payload["currentTier"]); name != "" {
			return name
		}
	}
	if name := antigravityDefaultAllowedTierLabel(payload["allowedTiers"]); name != "" {
		if ineligible {
			return name + " (Restricted)"
		}
		return name
	}
	return ""
}

func antigravityTierID(raw any) string {
	tier, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	if id, _ := tier["id"].(string); strings.TrimSpace(id) != "" {
		return strings.TrimSpace(id)
	}
	quotaTier, _ := tier["quotaTier"].(string)
	return strings.TrimSpace(quotaTier)
}

func antigravityTierLabel(raw any) string {
	tier, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	if quotaTier, _ := tier["quotaTier"].(string); strings.TrimSpace(quotaTier) != "" {
		return antigravityNormalizeTierValue(quotaTier)
	}
	name, _ := tier["name"].(string)
	if trimmed := strings.TrimSpace(name); trimmed != "" && !strings.EqualFold(trimmed, "Antigravity") {
		return trimmed
	}
	id, _ := tier["id"].(string)
	return antigravityNormalizeTierValue(id)
}

func antigravityDefaultAllowedTierLabel(raw any) string {
	tiers, _ := raw.([]any)
	for _, item := range tiers {
		tier, ok := item.(map[string]any)
		if !ok {
			continue
		}
		isDefault, _ := tier["isDefault"].(bool)
		if !isDefault {
			continue
		}
		return antigravityTierLabel(tier)
	}
	return ""
}

func antigravityDefaultAllowedTierID(raw any) string {
	tiers, _ := raw.([]any)
	for _, item := range tiers {
		tier, ok := item.(map[string]any)
		if !ok {
			continue
		}
		isDefault, _ := tier["isDefault"].(bool)
		if !isDefault {
			continue
		}
		return antigravityTierID(tier)
	}
	return ""
}

func antigravityHasIneligibleTiers(raw any) bool {
	tiers, ok := raw.([]any)
	return ok && len(tiers) > 0
}

func antigravityIneligibleTierMessage(raw any) string {
	tiers, ok := raw.([]any)
	if !ok || len(tiers) == 0 {
		return ""
	}
	messages := make([]string, 0, len(tiers))
	for _, item := range tiers {
		tier, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"reasonMessage", "validationErrorMessage", "reasonCode"} {
			value, _ := tier[key].(string)
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				messages = append(messages, trimmed)
				break
			}
		}
	}
	return strings.Join(messages, ", ")
}

func antigravityNormalizeTierValue(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return ""
	case "free-tier", "free":
		return "Free"
	case "standard-tier", "standard":
		return "Standard"
	case "legacy-tier", "legacy":
		return "Legacy"
	case "pro":
		return "Pro"
	case "ultra":
		return "Ultra"
	default:
		return strings.TrimSpace(raw)
	}
}
