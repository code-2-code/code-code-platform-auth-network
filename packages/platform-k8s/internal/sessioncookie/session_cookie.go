package sessioncookie

import (
	"fmt"
	"sort"
	"strings"
)

func Merge(requestCookie string, responseSetCookie string) string {
	cookies := Parse(requestCookie)
	for _, line := range strings.Split(responseSetCookie, "\n") {
		ApplyPair(cookies, setCookiePair(line))
	}
	return Header(cookies)
}

func Value(header string, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return strings.TrimSpace(Parse(header)[name])
}

func Parse(header string) map[string]string {
	cookies := map[string]string{}
	for _, pair := range strings.Split(header, ";") {
		ApplyPair(cookies, pair)
	}
	return cookies
}

func Header(cookies map[string]string) string {
	if len(cookies) == 0 {
		return ""
	}
	keys := make([]string, 0, len(cookies))
	for key := range cookies {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value := strings.TrimSpace(cookies[key])
		if value == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", strings.TrimSpace(key), value))
	}
	return strings.Join(parts, "; ")
}

func ApplyPair(cookies map[string]string, pair string) {
	if cookies == nil {
		return
	}
	key, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
	if !ok {
		return
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" {
		return
	}
	if value == "" {
		delete(cookies, key)
		return
	}
	cookies[key] = value
}

func setCookiePair(line string) string {
	headerValue := strings.TrimSpace(line)
	if strings.HasPrefix(strings.ToLower(headerValue), "set-cookie:") {
		headerValue = strings.TrimSpace(headerValue[len("set-cookie:"):])
	}
	if index := strings.Index(headerValue, ";"); index >= 0 {
		headerValue = headerValue[:index]
	}
	return headerValue
}
