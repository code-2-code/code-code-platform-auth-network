package googleaistudio

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"code-code.internal/platform-k8s/internal/egressauth"
)

func ReplaceHeader(input egressauth.ReplacementInput) (string, bool) {
	headerName := normalizeMaterialKey(input.HeaderName)
	current := strings.TrimSpace(input.CurrentValue)
	if headerName == "" || !strings.Contains(current, egressauth.Placeholder) {
		return "", false
	}
	switch headerName {
	case egressauth.HTTPHeaderAuthorization:
		now := input.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		token, ok := authorizationHeader(cookieHeaderMaterial(input.Material), requestOrigin(input), now.UTC())
		if !ok {
			return "", false
		}
		return strings.ReplaceAll(current, egressauth.Placeholder, token), true
	case "x_goog_api_key":
		return replacementValue(current, firstMaterial(input.Material, "page_api_key", "x_goog_api_key", egressauth.MaterialKeyAPIKey))
	default:
		base := input
		base.AdapterID = egressauth.AuthAdapterSessionCookieID
		return egressauth.ReplaceSimpleHeader(base, egressauth.SimpleReplacementRule{
			Mode:       egressauth.SimpleReplacementModeCookie,
			HeaderName: input.HeaderName,
		})
	}
}

func authorizationHeader(cookieHeader string, origin string, now time.Time) (string, bool) {
	origin = strings.TrimSpace(origin)
	if cookieHeader == "" || origin == "" {
		return "", false
	}
	timestamp := now.Unix()
	tokens := make([]string, 0, 3)
	if token := authorizationToken(cookieHeader, origin, timestamp, "SAPISIDHASH", "SAPISID", "__Secure-3PAPISID"); token != "" {
		tokens = append(tokens, token)
	}
	if token := authorizationToken(cookieHeader, origin, timestamp, "SAPISID1PHASH", "__Secure-1PAPISID"); token != "" {
		tokens = append(tokens, token)
	}
	if token := authorizationToken(cookieHeader, origin, timestamp, "SAPISID3PHASH", "__Secure-3PAPISID"); token != "" {
		tokens = append(tokens, token)
	}
	if len(tokens) == 0 {
		return "", false
	}
	return strings.Join(tokens, " "), true
}

func authorizationToken(cookieHeader, origin string, timestamp int64, prefix string, cookieNames ...string) string {
	var value string
	for _, name := range cookieNames {
		value = cookieValue(cookieHeader, name)
		if value != "" {
			break
		}
	}
	if value == "" {
		return ""
	}
	plain := fmt.Sprintf("%d %s %s", timestamp, value, strings.TrimSpace(origin))
	digest := sha1.Sum([]byte(plain))
	return fmt.Sprintf("%s %d_%s", prefix, timestamp, hex.EncodeToString(digest[:]))
}

func requestOrigin(input egressauth.ReplacementInput) string {
	if origin := strings.TrimSpace(input.Origin); origin != "" {
		return origin
	}
	if origin := requestHeader(input.RequestHeaders, "origin"); origin != "" {
		return origin
	}
	referer := requestHeader(input.RequestHeaders, "referer")
	if referer == "" {
		return ""
	}
	parsed, err := url.Parse(referer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func requestHeader(headers map[string]string, name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	for key, value := range headers {
		if strings.ToLower(strings.TrimSpace(key)) == name {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func replacementValue(current string, token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	current = strings.TrimSpace(current)
	if current == egressauth.Placeholder {
		return token, true
	}
	if strings.Contains(current, egressauth.Placeholder) {
		return strings.ReplaceAll(current, egressauth.Placeholder, token), true
	}
	return "", false
}

func firstMaterial(material map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := materialByKey(material, key); value != "" {
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

func cookieHeaderMaterial(material map[string]string) string {
	return materialByKey(material, egressauth.MaterialKeyCookie)
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
