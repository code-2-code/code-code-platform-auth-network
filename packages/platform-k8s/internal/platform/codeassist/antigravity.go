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
	antigravityLoadCodeAssistURL = "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
	antigravityOnboardUserURL    = "https://cloudcode-pa.googleapis.com/v1internal:onboardUser"
)

const (
	antigravityUserAgent      = "vscode/1.X.X (Antigravity/4.1.31)"
	antigravityAPIClient      = "google-cloud-sdk vscode_cloudshelleditor/0.1"
	antigravityClientMetadata = `{"ideType":"IDE_UNSPECIFIED","platform":"PLATFORM_UNSPECIFIED","pluginType":"GEMINI"}`
)

const (
	// AntigravityUserAgent is the Code Assist user-agent used by Antigravity.
	AntigravityUserAgent = antigravityUserAgent
	// AntigravityAPIClient is the x-goog-api-client header used by Antigravity.
	AntigravityAPIClient = antigravityAPIClient
	// AntigravityClientMetadata is the Code Assist client metadata header.
	AntigravityClientMetadata = antigravityClientMetadata
)

// LoadAntigravityCodeAssist loads Code Assist metadata for an Antigravity credential.
func LoadAntigravityCodeAssist(ctx context.Context, httpClient *http.Client, accessToken string) (map[string]any, error) {
	return loadAntigravityCodeAssist(ctx, httpClient, accessToken, "")
}

// LoadAntigravityCodeAssistWithProject loads Code Assist metadata with an existing companion project hint.
func LoadAntigravityCodeAssistWithProject(ctx context.Context, httpClient *http.Client, accessToken string, projectID string) (map[string]any, error) {
	return loadAntigravityCodeAssist(ctx, httpClient, accessToken, projectID)
}

// OnboardAntigravityUser creates a Code Assist workspace project for Antigravity when needed.
func OnboardAntigravityUser(ctx context.Context, httpClient *http.Client, accessToken string, tierID string) (string, error) {
	return onboardAntigravityUser(ctx, httpClient, accessToken, tierID, "")
}

// OnboardAntigravityUserWithProject onboards using an existing companion project hint when the selected tier requires it.
func OnboardAntigravityUserWithProject(ctx context.Context, httpClient *http.Client, accessToken string, tierID string, projectID string) (string, error) {
	return onboardAntigravityUser(ctx, httpClient, accessToken, tierID, projectID)
}

// AntigravityTierName returns the user-visible tier label from a Code Assist response.
func AntigravityTierName(payload map[string]any) string {
	return antigravityTierNameFromCodeAssistResponse(payload)
}

// AntigravityTierID returns the stable tier ID from a Code Assist response when present.
func AntigravityTierID(payload map[string]any) string {
	return antigravityTierIDFromCodeAssistResponse(payload)
}

// AntigravityDefaultTierID returns the default tier ID from allowed tiers.
func AntigravityDefaultTierID(payload map[string]any) string {
	return antigravityDefaultTierID(payload)
}

// AntigravityShouldOnboard reports whether loadCodeAssist returned an un-onboarded account.
func AntigravityShouldOnboard(payload map[string]any) bool {
	return antigravityShouldOnboard(payload)
}

// SetAntigravityURLsForTest overrides Antigravity Code Assist endpoints for tests.
func SetAntigravityURLsForTest(loadURL, onboardURL string) func() {
	previousLoadURL := antigravityLoadCodeAssistURL
	previousOnboardURL := antigravityOnboardUserURL
	antigravityLoadCodeAssistURL = loadURL
	antigravityOnboardUserURL = onboardURL
	return func() {
		antigravityLoadCodeAssistURL = previousLoadURL
		antigravityOnboardUserURL = previousOnboardURL
	}
}

func loadAntigravityCodeAssist(ctx context.Context, httpClient *http.Client, accessToken string, projectID string) (map[string]any, error) {
	body := map[string]any{
		"metadata": antigravityRequestMetadata(projectID),
	}
	if trimmedProjectID := strings.TrimSpace(projectID); trimmedProjectID != "" {
		body["cloudaicompanionProject"] = trimmedProjectID
	}
	return postAntigravityCloudCodeJSON(ctx, httpClient, antigravityLoadCodeAssistURL, accessToken, body)
}

func antigravityRequestMetadata(projectID string) map[string]string {
	metadata := map[string]string{
		"ideType":    "ANTIGRAVITY",
		"platform":   "PLATFORM_UNSPECIFIED",
		"pluginType": "GEMINI",
	}
	if trimmedProjectID := strings.TrimSpace(projectID); trimmedProjectID != "" {
		metadata["duetProject"] = trimmedProjectID
	}
	return metadata
}

func postAntigravityCloudCodeJSON(ctx context.Context, httpClient *http.Client, endpoint string, accessToken string, body map[string]any) (map[string]any, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: antigravity http client is nil")
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: marshal antigravity request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: create antigravity request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	outboundhttp.SetBearerAuthorization(request.Header, accessToken)
	request.Header.Set("User-Agent", antigravityUserAgent)
	request.Header.Set("X-Goog-Api-Client", antigravityAPIClient)
	request.Header.Set("Client-Metadata", antigravityClientMetadata)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: execute antigravity request: %w", err)
	}
	return decodeAntigravityCloudCodeJSON(response)
}

func getAntigravityCloudCodeJSON(ctx context.Context, httpClient *http.Client, endpoint string, accessToken string) (map[string]any, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: antigravity http client is nil")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: create antigravity operation request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	outboundhttp.SetBearerAuthorization(request.Header, accessToken)
	request.Header.Set("User-Agent", antigravityUserAgent)
	request.Header.Set("X-Goog-Api-Client", antigravityAPIClient)
	request.Header.Set("Client-Metadata", antigravityClientMetadata)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: execute antigravity operation request: %w", err)
	}
	return decodeAntigravityCloudCodeJSON(response)
}

func decodeAntigravityCloudCodeJSON(response *http.Response) (map[string]any, error) {
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(response.Body, codeAssistMaxBodyReadSize))
	if err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: read antigravity response: %w", err)
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("antigravity request unauthorized: status %d %s", response.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("clidefinitions/codeassist: antigravity request failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	parsed := map[string]any{}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return parsed, nil
	}
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return nil, fmt.Errorf("clidefinitions/codeassist: decode antigravity response: %w", err)
	}
	return parsed, nil
}
