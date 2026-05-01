package authservice

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"code-code.internal/go-contract/domainerror"
	"code-code.internal/platform-k8s/internal/sessioncookie"
)

const (
	mistralAdminBillingSessionSchemaID = "mistral-admin-billing-session"
	mistralAdminOrigin                 = "https://admin.mistral.ai"
	mistralAdminReferer                = "https://admin.mistral.ai/organization/usage"
	mistralAdminUserMePath             = "/api/users/me"

	mistralSessionMaterialCookie = "cookie"

	sessionMaterialAccountEmail = "account_email"
	sessionMaterialTierName     = "tier_name"
)

var (
	mistralAdminUserMeEndpoint = mistralAdminOrigin + mistralAdminUserMePath
	mistralAdminUserMeTimeout  = 5 * time.Second
)

func enrichSessionCredentialValues(ctx context.Context, schemaID string, values map[string]string) (map[string]string, error) {
	switch strings.TrimSpace(schemaID) {
	case mistralAdminBillingSessionSchemaID:
		return enrichMistralAdminSessionCredentialValues(ctx, values)
	default:
		return values, nil
	}
}

func enrichMistralAdminSessionCredentialValues(ctx context.Context, values map[string]string) (map[string]string, error) {
	values = trimCredentialValues(values)
	cookie := strings.TrimSpace(values[mistralSessionMaterialCookie])
	if cookie == "" {
		return nil, domainerror.NewValidation("platformk8s/authservice: mistral admin session cookie is required")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, mistralAdminUserMeEndpoint, nil)
	if err != nil {
		return nil, domainerror.NewValidation("platformk8s/authservice: build mistral account request: %v", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cookie", cookie)
	request.Header.Set("Origin", mistralAdminOrigin)
	request.Header.Set("Referer", mistralAdminReferer)
	if csrfToken := sessioncookie.Value(cookie, "csrftoken"); csrfToken != "" {
		request.Header.Set("X-CSRFTOKEN", csrfToken)
	}

	client := &http.Client{
		Timeout: mistralAdminUserMeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, domainerror.NewValidation("platformk8s/authservice: fetch mistral account summary: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, domainerror.NewValidation("platformk8s/authservice: fetch mistral account summary returned status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, domainerror.NewValidation("platformk8s/authservice: read mistral account summary: %v", err)
	}
	accountValues, err := parseMistralUserMeMaterialValues(body)
	if err != nil {
		return nil, err
	}
	if len(accountValues) == 0 {
		return nil, domainerror.NewValidation("platformk8s/authservice: mistral account summary is empty")
	}

	out := trimCredentialValues(values)
	for key, value := range accountValues {
		if out == nil {
			out = map[string]string{}
		}
		out[key] = value
	}
	return out, nil
}

type mistralUserMeResponse struct {
	Email        string                   `json:"email"`
	Organization *mistralOrganizationView `json:"organization"`
	Customer     *mistralCustomerView     `json:"customer"`
}

type mistralOrganizationView struct {
	OrgTier       string `json:"org_tier"`
	ActiveAPIPlan string `json:"active_api_plan"`
}

type mistralCustomerView struct {
	Platform *mistralCustomerPlatformView `json:"platform"`
}

type mistralCustomerPlatformView struct {
	APITiers string `json:"api_tiers"`
}

func parseMistralUserMeMaterialValues(body []byte) (map[string]string, error) {
	var payload mistralUserMeResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, domainerror.NewValidation("platformk8s/authservice: decode mistral account summary: %v", err)
	}
	values := map[string]string{}
	putSessionMaterialValue(values, sessionMaterialAccountEmail, payload.Email)
	putSessionMaterialValue(values, sessionMaterialTierName, mistralUserTierName(payload))
	return values, nil
}

func mistralUserTierName(payload mistralUserMeResponse) string {
	if payload.Organization != nil {
		if tier := strings.TrimSpace(payload.Organization.ActiveAPIPlan); tier != "" {
			return tier
		}
	}
	if payload.Customer != nil && payload.Customer.Platform != nil {
		if tier := strings.TrimSpace(payload.Customer.Platform.APITiers); tier != "" {
			return tier
		}
	}
	if payload.Organization != nil {
		return strings.TrimSpace(payload.Organization.OrgTier)
	}
	return ""
}

func putSessionMaterialValue(values map[string]string, key string, value string) {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return
	}
	values[key] = value
}
