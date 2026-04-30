package support

import (
	"testing"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

func TestValidateCredentialSubjectSummaryFieldsRejectsMissingJSONPointer(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "codex",
		Oauth: &supportv1.OAuthSupport{
			SubjectSummaryFields: []*supportv1.CredentialSubjectSummaryField{{
				FieldId:     "plan",
				Label:       "Plan",
				Source:      supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_ID_TOKEN_CLAIMS,
				ValueFormat: supportv1.CredentialSubjectSummaryValueFormat_CREDENTIAL_SUBJECT_SUMMARY_VALUE_FORMAT_PLAIN_TEXT,
			}},
		},
	}

	if err := ValidateCredentialSubjectSummaryFields(pkg); err == nil {
		t.Fatal("ValidateCredentialSubjectSummaryFields() error = nil, want error")
	}
}

func TestValidateCredentialSubjectSummaryFieldsAcceptsArtifactEmailField(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "gemini-cli",
		Oauth: &supportv1.OAuthSupport{
			SubjectSummaryFields: []*supportv1.CredentialSubjectSummaryField{{
				FieldId:     "account-email",
				Label:       "Account",
				Source:      supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_ARTIFACT_SUBJECT_EMAIL,
				ValueFormat: supportv1.CredentialSubjectSummaryValueFormat_CREDENTIAL_SUBJECT_SUMMARY_VALUE_FORMAT_MASK_EMAIL,
			}},
		},
	}

	if err := ValidateCredentialSubjectSummaryFields(pkg); err != nil {
		t.Fatalf("ValidateCredentialSubjectSummaryFields() error = %v", err)
	}
}

func TestValidateCredentialSubjectSummaryFieldsAcceptsCredentialMaterialField(t *testing.T) {
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

	if err := ValidateCredentialSubjectSummaryFields(pkg); err != nil {
		t.Fatalf("ValidateCredentialSubjectSummaryFields() error = %v", err)
	}
}
