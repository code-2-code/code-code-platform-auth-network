package codeassist

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
)

var (
	geminiCodeAssistURL        = "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
	geminiRetrieveUserQuotaURL = "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota"
)

const codeAssistMaxBodyReadSize = 1 << 14

// LoadGeminiCodeAssist loads Google Code Assist metadata for a Gemini CLI credential.
func LoadGeminiCodeAssist(ctx context.Context, httpClient *http.Client, accessToken string, projectID string) (map[string]any, error) {
	return loadGeminiCodeAssist(ctx, httpClient, accessToken, projectID)
}

// GeminiProjectID returns the project ID embedded in a Code Assist response.
func GeminiProjectID(payload map[string]any) string {
	return geminiProjectIDFromCodeAssistResponse(payload)
}

// GeminiTierName returns the user-visible tier label embedded in a Code Assist response.
func GeminiTierName(payload map[string]any) string {
	return geminiTierNameFromCodeAssistResponse(payload)
}

// LoadGeminiUserQuota loads Gemini user quota buckets for a Code Assist project.
func LoadGeminiUserQuota(ctx context.Context, httpClient *http.Client, accessToken string, projectID string) (map[string]any, error) {
	return loadGeminiUserQuota(ctx, httpClient, accessToken, projectID)
}

// SetGeminiURLsForTest overrides Google Code Assist endpoints for tests.
func SetGeminiURLsForTest(codeAssistURL, quotaURL string) func() {
	previousCodeAssistURL := geminiCodeAssistURL
	previousQuotaURL := geminiRetrieveUserQuotaURL
	geminiCodeAssistURL = codeAssistURL
	geminiRetrieveUserQuotaURL = quotaURL
	return func() {
		geminiCodeAssistURL = previousCodeAssistURL
		geminiRetrieveUserQuotaURL = previousQuotaURL
	}
}

func loadGeminiCodeAssist(ctx context.Context, httpClient *http.Client, accessToken string, projectID string) (map[string]any, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: gemini http client is nil")
	}
	body := map[string]any{
		"metadata": map[string]string{
			"ideType":    "IDE_UNSPECIFIED",
			"platform":   "PLATFORM_UNSPECIFIED",
			"pluginType": "GEMINI",
		},
	}
	if trimmedProject := strings.TrimSpace(projectID); trimmedProject != "" {
		body["cloudaicompanionProject"] = trimmedProject
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: marshal gemini loadCodeAssist request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, geminiCodeAssistURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: create gemini loadCodeAssist request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	outboundhttp.SetBearerAuthorization(request.Header, accessToken)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: execute gemini loadCodeAssist request: %w", err)
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(response.Body, codeAssistMaxBodyReadSize))
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: read gemini loadCodeAssist response: %w", err)
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("gemini loadCodeAssist unauthorized: status %d %s", response.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("clidefinitions/codeassist: gemini loadCodeAssist failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	parsed := map[string]any{}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return parsed, nil
	}
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: decode gemini loadCodeAssist response: %w", err)
	}
	return parsed, nil
}

func geminiProjectIDFromCodeAssistResponse(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	if projectID := geminiProjectIDFromProjectValue(payload["cloudaicompanionProject"]); projectID != "" {
		return projectID
	}
	if projectID := geminiProjectIDFromProjectValue(payload["projectId"]); projectID != "" {
		return projectID
	}
	return ""
}

func geminiTierNameFromCodeAssistResponse(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	if name := geminiTierName(payload["paidTier"]); name != "" {
		return name
	}
	return geminiTierName(payload["currentTier"])
}

func geminiTierName(raw any) string {
	tier, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	name, _ := tier["name"].(string)
	return strings.TrimSpace(name)
}

func loadGeminiUserQuota(ctx context.Context, httpClient *http.Client, accessToken, projectID string) (map[string]any, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, fmt.Errorf("clidefinitions/codeassist: gemini project id is empty")
	}
	if httpClient == nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: gemini http client is nil")
	}
	payload, err := json.Marshal(map[string]string{
		"project": strings.TrimSpace(projectID),
	})
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: marshal gemini retrieveUserQuota request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, geminiRetrieveUserQuotaURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: create gemini retrieveUserQuota request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	outboundhttp.SetBearerAuthorization(request.Header, accessToken)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: execute gemini retrieveUserQuota request: %w", err)
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(response.Body, codeAssistMaxBodyReadSize))
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: read gemini retrieveUserQuota response: %w", err)
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("gemini retrieveUserQuota unauthorized: status %d %s", response.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("clidefinitions/codeassist: gemini retrieveUserQuota failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	parsed := map[string]any{}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return parsed, nil
	}
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: decode gemini retrieveUserQuota response: %w", err)
	}
	return parsed, nil
}


