package egresspolicies

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

func destinationLabelValue(destinationID string) string {
	return resourceSuffix(destinationID, 48)
}

func serviceEntryName(destinationID string) string {
	return resourceName(resourcePrefixServiceEntry, destinationID)
}

func authorizationPolicyName(destinationID string) string {
	return resourceName(resourcePrefixAuthz, destinationID)
}

func l7EgressGatewayName(destinationID string) string {
	return resourceNameMax(resourcePrefixL7Gateway, destinationID, 57)
}

func l7EgressGatewayOptionsName(destinationID string) string {
	return resourceName(resourcePrefixL7GatewayOptions, destinationID)
}

func l7EgressGatewayServiceName(destinationID string) string {
	return l7EgressGatewayName(destinationID) + "-istio"
}

func gatewayDestinationRuleName(destinationID string) string {
	return resourceName(resourcePrefixGatewayMTLS, destinationID)
}

func directHTTPRouteName(routeID string) string {
	return resourceName(resourcePrefixDirectHTTPRoute, routeID)
}

func forwardHTTPRouteName(routeID string) string {
	return resourceName(resourcePrefixForwardHTTPRoute, routeID)
}

func destinationRuleName(destinationID string) string {
	return resourceName(resourcePrefixDestinationRule, destinationID)
}

func dynamicHeaderAuthzPolicyName(providerName string) string {
	if strings.TrimSpace(providerName) == "" {
		return resourceNameDynamicHeaderAuthz
	}
	return resourceName(resourceNameDynamicHeaderAuthz, providerName)
}

func resourceName(prefix string, value string) string {
	return resourceNameMax(prefix, value, 63)
}

func resourceNameMax(prefix string, value string, maxLen int) string {
	suffix := resourceSuffix(value, maxLen-len(prefix)-1)
	if suffix == "" {
		suffix = "default"
	}
	return prefix + "-" + suffix
}

func resourceSuffix(value string, maxLen int) string {
	value = strings.TrimSpace(strings.ToLower(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	base := strings.Trim(b.String(), "-")
	hash := shortHash(value)
	if maxLen <= len(hash)+1 {
		return hash[:maxLen]
	}
	limit := maxLen - len(hash) - 1
	if len(base) > limit {
		base = strings.Trim(base[:limit], "-")
	}
	if base == "" {
		return hash
	}
	return base + "-" + hash
}

func shortHash(value string) string {
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:])[:10]
}
