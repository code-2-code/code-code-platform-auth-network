package httpauth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

const bearerPrefix = "bearer "

func HasBearerAuthorization(authorizationHeader string, token string) bool {
	authorizationHeader = strings.TrimSpace(authorizationHeader)
	token = strings.TrimSpace(token)
	if authorizationHeader == "" || token == "" {
		return false
	}
	if len(authorizationHeader) <= len(bearerPrefix) || !strings.EqualFold(authorizationHeader[:len(bearerPrefix)], bearerPrefix) {
		return false
	}
	providedToken := strings.TrimSpace(authorizationHeader[len(bearerPrefix):])
	return subtle.ConstantTimeCompare([]byte(providedToken), []byte(token)) == 1
}

func SetBearerAuthorization(request *http.Request, token string) {
	if request == nil {
		return
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	request.Header.Set("Authorization", "Bearer "+token)
}
