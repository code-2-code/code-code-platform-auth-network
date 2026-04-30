package codeassist

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var antigravityOnboardPollDelay = 2 * time.Second

// AntigravityProjectResolutionError returns the user-facing reason when Antigravity did not return a project ID.
func AntigravityProjectResolutionError(payload map[string]any) error {
	if message := antigravityIneligibleTierMessage(payload["ineligibleTiers"]); message != "" {
		return fmt.Errorf("clidefinitions/codeassist: antigravity account is not eligible: %s", message)
	}
	return fmt.Errorf("clidefinitions/codeassist: antigravity project id is required for this account")
}

// AntigravityOnboardMissingProjectIDError marks an onboard response that completed without a companion project ID.
type AntigravityOnboardMissingProjectIDError struct {
	Message string
}

func (e *AntigravityOnboardMissingProjectIDError) Error() string {
	if strings.TrimSpace(e.Message) != "" {
		return fmt.Sprintf("clidefinitions/codeassist: antigravity onboardUser response missing project id: %s", strings.TrimSpace(e.Message))
	}
	return "clidefinitions/codeassist: antigravity onboardUser response missing project id"
}

// IsAntigravityOnboardMissingProjectID reports whether err is a completed onboard response with no project ID.
func IsAntigravityOnboardMissingProjectID(err error) bool {
	var target *AntigravityOnboardMissingProjectIDError
	return errors.As(err, &target)
}

func onboardAntigravityUser(ctx context.Context, httpClient *http.Client, accessToken string, tierID string, projectID string) (string, error) {
	if strings.TrimSpace(tierID) == "" {
		tierID = "legacy-tier"
	} else {
		tierID = strings.TrimSpace(tierID)
	}
	body := map[string]any{
		"tierId":   tierID,
		"metadata": antigravityRequestMetadata(projectID),
	}
	if trimmedProjectID := strings.TrimSpace(projectID); trimmedProjectID != "" && tierID != "free-tier" {
		body["cloudaicompanionProject"] = trimmedProjectID
	}
	payload, err := postAntigravityCloudCodeJSON(ctx, httpClient, antigravityOnboardUserURL, accessToken, body)
	if err != nil {
		return "", err
	}
	payload, err = waitAntigravityOnboardOperation(ctx, httpClient, accessToken, payload)
	if err != nil {
		return "", err
	}
	if projectID := antigravityProjectIDFromOnboardResponse(payload); projectID != "" {
		return projectID, nil
	}
	return "", &AntigravityOnboardMissingProjectIDError{
		Message: antigravityOnboardFailureMessage(payload),
	}
}

func waitAntigravityOnboardOperation(ctx context.Context, httpClient *http.Client, accessToken string, payload map[string]any) (map[string]any, error) {
	for attempt := 0; attempt < 5; attempt++ {
		done, _ := payload["done"].(bool)
		if done {
			return payload, nil
		}
		operationName, _ := payload["name"].(string)
		operationName = strings.TrimSpace(operationName)
		if operationName == "" {
			return payload, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(antigravityOnboardPollDelay):
		}
		nextPayload, err := getAntigravityCloudCodeJSON(ctx, httpClient, antigravityOperationURL(operationName), accessToken)
		if err != nil {
			return nil, err
		}
		payload = nextPayload
	}
	return payload, nil
}

func antigravityOperationURL(operationName string) string {
	trimmed := strings.TrimSpace(operationName)
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return trimmed
	}
	base := antigravityOnboardUserURL
	if index := strings.LastIndex(base, ":"); index > strings.LastIndex(base, "/") {
		base = base[:index]
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(trimmed, "/")
}

func antigravityProjectIDFromOnboardResponse(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	if projectID := geminiProjectIDFromCodeAssistResponse(payload); projectID != "" {
		return projectID
	}
	for _, key := range []string{"response", "metadata"} {
		nested, _ := payload[key].(map[string]any)
		if projectID := geminiProjectIDFromCodeAssistResponse(nested); projectID != "" {
			return projectID
		}
	}
	return ""
}

func antigravityOnboardFailureMessage(payload map[string]any) string {
	for _, key := range []string{"error", "response", "metadata", "status"} {
		if message := antigravityStatusMessage(payload[key]); message != "" {
			return message
		}
	}
	return ""
}

func antigravityStatusMessage(raw any) string {
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value)
	case map[string]any:
		for _, key := range []string{"displayMessage", "message", "reasonMessage", "description"} {
			if message, ok := value[key].(string); ok {
				if trimmed := strings.TrimSpace(message); trimmed != "" {
					return trimmed
				}
			}
		}
		for _, key := range []string{"error", "status"} {
			if message := antigravityStatusMessage(value[key]); message != "" {
				return message
			}
		}
	}
	return ""
}
