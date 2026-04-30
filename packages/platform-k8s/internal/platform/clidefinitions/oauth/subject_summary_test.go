package oauth

import (
	"testing"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
)

func TestResolveCredentialSubjectSummaryMasksEmail(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "codex",
		Oauth: &supportv1.OAuthSupport{
			SubjectSummaryFields: []*supportv1.CredentialSubjectSummaryField{{
				FieldId:     "account-email",
				Label:       "Account",
				Source:      supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_ARTIFACT_SUBJECT_EMAIL,
				ValueFormat: supportv1.CredentialSubjectSummaryValueFormat_CREDENTIAL_SUBJECT_SUMMARY_VALUE_FORMAT_MASK_EMAIL,
			}},
		},
	}

	fields, err := ResolveCredentialSubjectSummary(pkg, &credentialcontract.OAuthArtifact{
		AccountEmail: "dev@example.com",
	}, nil)
	if err != nil {
		t.Fatalf("ResolveCredentialSubjectSummary() error = %v", err)
	}
	if got, want := len(fields), 1; got != want {
		t.Fatalf("len(fields) = %d, want %d", got, want)
	}
	if got, want := fields[0].Value, "d***v@example.com"; got != want {
		t.Fatalf("fields[0].value = %q, want %q", got, want)
	}
}

func TestResolveCredentialSubjectSummaryReadsTokenResponseValue(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "codex",
		Oauth: &supportv1.OAuthSupport{
			SubjectSummaryFields: []*supportv1.CredentialSubjectSummaryField{{
				FieldId:     "tier",
				Label:       "Tier",
				Source:      supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_TOKEN_RESPONSE,
				JsonPointer: "/tier",
				ValueFormat: supportv1.CredentialSubjectSummaryValueFormat_CREDENTIAL_SUBJECT_SUMMARY_VALUE_FORMAT_PLAIN_TEXT,
			}},
		},
	}

	fields, err := ResolveCredentialSubjectSummary(pkg, &credentialcontract.OAuthArtifact{
		TokenResponseJSON: `{"tier":"Pro"}`,
	}, nil)
	if err != nil {
		t.Fatalf("ResolveCredentialSubjectSummary() error = %v", err)
	}
	if got, want := fields[0].Value, "Pro"; got != want {
		t.Fatalf("fields[0].value = %q, want %q", got, want)
	}
}

func TestResolveCredentialSubjectSummaryReadsCredentialMaterialValue(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "gemini-cli",
		Oauth: &supportv1.OAuthSupport{
			SubjectSummaryFields: []*supportv1.CredentialSubjectSummaryField{{
				FieldId:     "project",
				Label:       "Project",
				Source:      supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_CREDENTIAL_MATERIAL,
				MaterialKey: "project_id",
				ValueFormat: supportv1.CredentialSubjectSummaryValueFormat_CREDENTIAL_SUBJECT_SUMMARY_VALUE_FORMAT_PLAIN_TEXT,
			}},
		},
	}

	fields, err := ResolveCredentialSubjectSummary(pkg, &credentialcontract.OAuthArtifact{
		AccountEmail: "dev@example.com",
	}, func(materialKey string) (string, error) {
		if got, want := materialKey, "project_id"; got != want {
			t.Fatalf("materialKey = %q, want %q", got, want)
		}
		return "workspacecli-489315", nil
	})
	if err != nil {
		t.Fatalf("ResolveCredentialSubjectSummary() error = %v", err)
	}
	if got, want := fields[0].Value, "workspacecli-489315"; got != want {
		t.Fatalf("fields[0].value = %q, want %q", got, want)
	}
}
