package authservice

import (
	"testing"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
)

func TestNormalizeSessionInputValuesUsesDeclaredStoredFields(t *testing.T) {
	values, required, err := normalizeSessionInputValues(testSessionInputForm(), map[string]string{
		"access_token": " token ",
	}, nil)
	if err != nil {
		t.Fatalf("normalizeSessionInputValues() error = %v", err)
	}
	if got, want := values["access_token"], "token"; got != want {
		t.Fatalf("access_token = %q, want %q", got, want)
	}
	if len(required) != 1 || required[0] != "access_token" {
		t.Fatalf("required = %#v, want access_token", required)
	}
}

func TestNormalizeSessionInputValuesRejectsUndeclaredFields(t *testing.T) {
	_, _, err := normalizeSessionInputValues(testSessionInputForm(), map[string]string{
		"authorization": "Bearer token",
	}, nil)
	if err == nil {
		t.Fatal("normalizeSessionInputValues() error = nil, want undeclared field error")
	}
}

func TestNormalizeSessionInputValuesMergesDeclaredSetCookie(t *testing.T) {
	form := testCookieSessionInputForm()
	values, _, err := normalizeSessionInputValues(form, map[string]string{
		"cookie":              "SID=old; HSID=old",
		"response_set_cookie": "Set-Cookie: SID=new; Path=/\nHSID=fresh; Path=/",
	}, nil)
	if err != nil {
		t.Fatalf("normalizeSessionInputValues() error = %v", err)
	}
	if got, want := values["cookie"], "HSID=fresh; SID=new"; got != want {
		t.Fatalf("cookie = %q, want %q", got, want)
	}
}

func TestNormalizeSessionInputValuesMergesSetCookieIntoExistingMaterial(t *testing.T) {
	form := testCookieSessionInputForm()
	values, _, err := normalizeSessionInputValues(form, map[string]string{
		"response_set_cookie": "Set-Cookie: SID=new; Path=/",
	}, map[string]string{"cookie": "SID=old; HSID=old"})
	if err != nil {
		t.Fatalf("normalizeSessionInputValues() error = %v", err)
	}
	if got, want := values["cookie"], "HSID=old; SID=new"; got != want {
		t.Fatalf("cookie = %q, want %q", got, want)
	}
}

func TestNormalizeSessionInputValuesRequiresMergeTarget(t *testing.T) {
	_, _, err := normalizeSessionInputValues(testCookieSessionInputForm(), map[string]string{
		"response_set_cookie": "Set-Cookie: SID=new; Path=/",
	}, nil)
	if err == nil {
		t.Fatal("normalizeSessionInputValues() error = nil, want missing merge target error")
	}
}

func testSessionInputForm() *observabilityv1.QuotaQueryInputForm {
	return &observabilityv1.QuotaQueryInputForm{
		SchemaId:    "mistral-billing-session",
		Title:       "Update Mistral Session Token",
		ActionLabel: "Update Session Token",
		Fields: []*observabilityv1.QuotaQueryInputField{{
			FieldId:     "access_token",
			Label:       "Session token",
			Required:    true,
			Sensitive:   true,
			Control:     observabilityv1.QuotaQueryInputControl_QUOTA_QUERY_INPUT_CONTROL_PASSWORD,
			Persistence: observabilityv1.QuotaQueryInputPersistence_QUOTA_QUERY_INPUT_PERSISTENCE_STORED_MATERIAL,
		}},
	}
}

func testCookieSessionInputForm() *observabilityv1.QuotaQueryInputForm {
	return &observabilityv1.QuotaQueryInputForm{
		SchemaId:    "google-ai-studio-session",
		Title:       "Update AI Studio Session",
		ActionLabel: "Update AI Studio Session",
		Fields: []*observabilityv1.QuotaQueryInputField{
			{
				FieldId:     "cookie",
				Label:       "Request Cookie",
				Required:    true,
				Control:     observabilityv1.QuotaQueryInputControl_QUOTA_QUERY_INPUT_CONTROL_TEXTAREA,
				Persistence: observabilityv1.QuotaQueryInputPersistence_QUOTA_QUERY_INPUT_PERSISTENCE_STORED_MATERIAL,
			},
			{
				FieldId:       "response_set_cookie",
				Label:         "Response Set-Cookie",
				Control:       observabilityv1.QuotaQueryInputControl_QUOTA_QUERY_INPUT_CONTROL_TEXTAREA,
				Persistence:   observabilityv1.QuotaQueryInputPersistence_QUOTA_QUERY_INPUT_PERSISTENCE_TRANSIENT,
				TargetFieldId: "cookie",
				Transform:     observabilityv1.QuotaQueryInputValueTransform_QUOTA_QUERY_INPUT_VALUE_TRANSFORM_MERGE_SET_COOKIE,
			},
		},
	}
}
