package codeassist

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOnboardAntigravityUserPollsOperation(t *testing.T) {
	previousDelay := antigravityOnboardPollDelay
	antigravityOnboardPollDelay = time.Millisecond
	defer func() {
		antigravityOnboardPollDelay = previousDelay
	}()

	var onboardCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1internal:onboardUser":
			onboardCalled = true
			if r.Method != http.MethodPost {
				t.Fatalf("onboard method = %s, want POST", r.Method)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if got, want := body["tierId"], "standard-tier"; got != want {
				t.Fatalf("tierId = %v, want %q", got, want)
			}
			if got, want := body["cloudaicompanionProject"], "workspacecli-existing"; got != want {
				t.Fatalf("cloudaicompanionProject = %v, want %q", got, want)
			}
			metadata, _ := body["metadata"].(map[string]any)
			if got, want := metadata["duetProject"], "workspacecli-existing"; got != want {
				t.Fatalf("metadata.duetProject = %v, want %q", got, want)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name": "operations/onboard-1",
				"done": false,
			})
		case "/v1internal/operations/onboard-1":
			if r.Method != http.MethodGet {
				t.Fatalf("operation method = %s, want GET", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"done": true,
				"response": map[string]any{
					"cloudaicompanionProject": map[string]any{
						"name": "projects/workspacecli-polled",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	defer SetAntigravityURLsForTest(server.URL+"/v1internal:loadCodeAssist", server.URL+"/v1internal:onboardUser")()

	projectID, err := OnboardAntigravityUserWithProject(context.Background(), server.Client(), "access-token", "standard-tier", "workspacecli-existing")
	if err != nil {
		t.Fatalf("OnboardAntigravityUserWithProject() error = %v", err)
	}
	if !onboardCalled {
		t.Fatal("onboard endpoint was not called")
	}
	if got, want := projectID, "workspacecli-polled"; got != want {
		t.Fatalf("projectID = %q, want %q", got, want)
	}
}

func TestOnboardAntigravityUserMissingProjectIncludesStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"done": true,
			"response": map[string]any{
				"status": map[string]any{
					"displayMessage": "Your current account is not eligible for Antigravity.",
				},
			},
		})
	}))
	defer server.Close()
	defer SetAntigravityURLsForTest(server.URL+"/load", server.URL+"/onboard")()

	_, err := OnboardAntigravityUser(context.Background(), server.Client(), "access-token", "free-tier")
	if err == nil {
		t.Fatal("OnboardAntigravityUser() error = nil, want missing project error")
	}
	if !IsAntigravityOnboardMissingProjectID(err) {
		t.Fatalf("IsAntigravityOnboardMissingProjectID() = false for %v", err)
	}
	if !strings.Contains(err.Error(), "not eligible for Antigravity") {
		t.Fatalf("error = %v, want status message", err)
	}
}

func TestGeminiProjectIDAcceptsResourceName(t *testing.T) {
	payload := map[string]any{
		"cloudaicompanionProject": map[string]any{
			"name": "projects/workspacecli-from-name",
		},
	}
	if got, want := GeminiProjectID(payload), "workspacecli-from-name"; got != want {
		t.Fatalf("GeminiProjectID() = %q, want %q", got, want)
	}
}
