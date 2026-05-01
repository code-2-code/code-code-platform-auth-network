package authservice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseMistralUserMeMaterialValuesKeepsOnlyAccountSummary(t *testing.T) {
	values, err := parseMistralUserMeMaterialValues([]byte(`{
		"uuid": "account-1",
		"name": "Coding Wee",
		"email": "dev@example.com",
		"organization": {
			"uuid": "org-1",
			"name": "pood1e",
			"customer_uuid": "customer-1",
			"org_tier": "B",
			"active_api_plan": "FREE"
		},
		"workspace": {
			"uuid": "workspace-1",
			"name": "Default Workspace"
		},
		"customer": {
			"uuid": "customer-1",
			"platform": {"api_tiers": "FR"}
		}
	}`))
	if err != nil {
		t.Fatalf("parseMistralUserMeMaterialValues() error = %v", err)
	}
	if got, want := values[sessionMaterialAccountEmail], "dev@example.com"; got != want {
		t.Fatalf("account email = %q, want %q", got, want)
	}
	if got, want := values[sessionMaterialTierName], "FREE"; got != want {
		t.Fatalf("tier name = %q, want %q", got, want)
	}
	if got, want := len(values), 2; got != want {
		t.Fatalf("material value count = %d, want %d", got, want)
	}
}

func TestEnrichMistralAdminSessionCredentialValuesFetchesAccountSummary(t *testing.T) {
	var seen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = true
		if got, want := r.URL.Path, "/api/users/me"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Cookie"), "ory_session_test=abc; csrftoken=csrf-1"; got != want {
			t.Fatalf("Cookie = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("X-CSRFTOKEN"), "csrf-1"; got != want {
			t.Fatalf("X-CSRFTOKEN = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Origin"), mistralAdminOrigin; got != want {
			t.Fatalf("Origin = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Referer"), mistralAdminReferer; got != want {
			t.Fatalf("Referer = %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"uuid": "account-1",
			"email": "dev@example.com",
			"organization": {"org_tier": "B", "active_api_plan": "FREE"},
			"customer": {"platform": {"api_tiers": "FR"}}
		}`))
	}))
	defer server.Close()

	previousEndpoint := mistralAdminUserMeEndpoint
	mistralAdminUserMeEndpoint = server.URL + "/api/users/me"
	defer func() {
		mistralAdminUserMeEndpoint = previousEndpoint
	}()

	values, err := enrichSessionCredentialValues(context.Background(), mistralAdminBillingSessionSchemaID, map[string]string{
		mistralSessionMaterialCookie: "ory_session_test=abc; csrftoken=csrf-1",
		sessionMaterialAccountEmail:  "old@example.com",
	})
	if err != nil {
		t.Fatalf("enrichSessionCredentialValues() error = %v", err)
	}
	if !seen {
		t.Fatal("mistral account endpoint was not called")
	}
	if got, want := values[mistralSessionMaterialCookie], "ory_session_test=abc; csrftoken=csrf-1"; got != want {
		t.Fatalf("cookie = %q, want %q", got, want)
	}
	if got, want := values[sessionMaterialAccountEmail], "dev@example.com"; got != want {
		t.Fatalf("account email = %q, want %q", got, want)
	}
	if got, want := values[sessionMaterialTierName], "FREE"; got != want {
		t.Fatalf("tier name = %q, want %q", got, want)
	}
}

func TestEnrichSessionCredentialValuesSkipsOtherSchemas(t *testing.T) {
	values := map[string]string{"cookie": "session"}
	out, err := enrichSessionCredentialValues(context.Background(), "other-session-schema", values)
	if err != nil {
		t.Fatalf("enrichSessionCredentialValues() error = %v", err)
	}
	if out["cookie"] != "session" {
		t.Fatalf("cookie = %q, want session", out["cookie"])
	}
}
