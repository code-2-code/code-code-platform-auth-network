package egressauth

import "testing"

func TestReplaceSimpleHeaderRequiresExplicitRule(t *testing.T) {
	got, ok := ReplaceSimpleHeader(ReplacementInput{
		HeaderName:        "authorization",
		HeaderValuePrefix: "Bearer",
		CurrentValue:      "Bearer " + Placeholder,
		Material: map[string]string{
			"access_token": "test-token",
		},
	})
	if ok {
		t.Fatalf("ReplaceHeader() ok = true, value = %q", got)
	}
}

func TestReplaceSimpleHeaderExplicitBearerRule(t *testing.T) {
	got, ok := ReplaceSimpleHeader(ReplacementInput{
		HeaderName:        "authorization",
		HeaderValuePrefix: "Bearer",
		CurrentValue:      "Bearer " + Placeholder,
		Material: map[string]string{
			"access_token": "test-token",
		},
	}, SimpleReplacementRule{
		Mode:       SimpleReplacementModeBearer,
		HeaderName: "authorization",
	})
	if !ok {
		t.Fatal("ReplaceHeader() ok = false")
	}
	if got != "Bearer test-token" {
		t.Fatalf("ReplaceHeader() = %q, want %q", got, "Bearer test-token")
	}
}

func TestReplaceSimpleHeaderSessionCookie(t *testing.T) {
	got, ok := ReplaceSimpleHeader(ReplacementInput{
		AdapterID:    AuthAdapterSessionCookieID,
		HeaderName:   "cookie",
		CurrentValue: "authjs.session-token=" + Placeholder + "; other=value",
		Material: map[string]string{
			"authjs.session-token": "session-token",
		},
	}, SimpleReplacementRule{Mode: SimpleReplacementModeCookie, HeaderName: "cookie"})
	if !ok {
		t.Fatal("ReplaceHeader() ok = false")
	}
	if got != "authjs.session-token=session-token; other=value" {
		t.Fatalf("ReplaceHeader() = %q", got)
	}
}

func TestReplaceSimpleHeaderUsesDeclarativeRule(t *testing.T) {
	got, ok := ReplaceSimpleHeader(ReplacementInput{
		HeaderName:   "authorization",
		CurrentValue: Placeholder,
		Material: map[string]string{
			"id_token":     "id-token",
			"access_token": "access-token",
		},
	}, SimpleReplacementRule{
		HeaderName:  "authorization",
		MaterialKey: "id_token",
		Template:    "Bearer " + Placeholder,
	})
	if !ok {
		t.Fatal("ReplaceSimpleHeader() ok = false")
	}
	if got != "Bearer id-token" {
		t.Fatalf("ReplaceSimpleHeader() = %q, want %q", got, "Bearer id-token")
	}
}

func TestReplaceSimpleHeaderCookieModeRequiresHeaderName(t *testing.T) {
	got, ok := ReplaceSimpleHeader(ReplacementInput{
		HeaderName:   "cookie",
		CurrentValue: Placeholder,
		Material: map[string]string{
			"cookie": "session=value",
		},
	}, SimpleReplacementRule{Mode: SimpleReplacementModeCookie})
	if ok {
		t.Fatalf("ReplaceSimpleHeader() ok = true, value = %q", got)
	}
	names := SimpleReplacementRuleHeaderNames([]SimpleReplacementRule{{Mode: SimpleReplacementModeCookie}})
	if len(names) != 0 {
		t.Fatalf("SimpleReplacementRuleHeaderNames() = %#v", names)
	}
}

func TestReplaceSimpleHeaderCookieMode(t *testing.T) {
	got, ok := ReplaceSimpleHeader(ReplacementInput{
		HeaderName:   "cookie",
		CurrentValue: Placeholder,
		Material: map[string]string{
			"cookie": "session=value",
		},
	}, SimpleReplacementRule{Mode: SimpleReplacementModeCookie, HeaderName: "cookie"})
	if !ok {
		t.Fatal("ReplaceSimpleHeader() ok = false")
	}
	if got != "session=value" {
		t.Fatalf("ReplaceSimpleHeader() = %q, want %q", got, "session=value")
	}
	names := SimpleReplacementRuleHeaderNames([]SimpleReplacementRule{{Mode: SimpleReplacementModeCookie, HeaderName: "cookie"}})
	if len(names) != 1 || names[0] != "cookie" {
		t.Fatalf("SimpleReplacementRuleHeaderNames() = %#v", names)
	}
}

func TestReplaceSimpleHeaderBearerModeDefaults(t *testing.T) {
	got, ok := ReplaceSimpleHeader(ReplacementInput{
		HeaderName:   "authorization",
		CurrentValue: Placeholder,
		Material: map[string]string{
			"access_token": "token",
		},
	}, SimpleReplacementRule{Mode: SimpleReplacementModeBearer, HeaderName: "authorization"})
	if !ok {
		t.Fatal("ReplaceSimpleHeader() ok = false")
	}
	if got != "Bearer token" {
		t.Fatalf("ReplaceSimpleHeader() = %q, want %q", got, "Bearer token")
	}
}
