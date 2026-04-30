package support

import (
	"fmt"
	"strings"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

func ValidateCredentialSubjectSummaryFields(pkg *supportv1.CLI) error {
	if pkg == nil || pkg.GetOauth() == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(pkg.GetOauth().GetSubjectSummaryFields()))
	for _, field := range pkg.GetOauth().GetSubjectSummaryFields() {
		if field == nil {
			return fmt.Errorf("platformk8s/clidefinitions: oauth subject summary field is nil for %q", pkg.GetCliId())
		}
		fieldID := strings.TrimSpace(field.GetFieldId())
		if fieldID == "" {
			return fmt.Errorf("platformk8s/clidefinitions: oauth subject summary field_id is empty for %q", pkg.GetCliId())
		}
		if _, ok := seen[fieldID]; ok {
			return fmt.Errorf("platformk8s/clidefinitions: duplicate oauth subject summary field_id %q for %q", fieldID, pkg.GetCliId())
		}
		seen[fieldID] = struct{}{}
		if strings.TrimSpace(field.GetLabel()) == "" {
			return fmt.Errorf("platformk8s/clidefinitions: oauth subject summary label is empty for %q %q", pkg.GetCliId(), fieldID)
		}
		if field.GetSource() == supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_UNSPECIFIED {
			return fmt.Errorf("platformk8s/clidefinitions: oauth subject summary source is unspecified for %q %q", pkg.GetCliId(), fieldID)
		}
		if field.GetValueFormat() == supportv1.CredentialSubjectSummaryValueFormat_CREDENTIAL_SUBJECT_SUMMARY_VALUE_FORMAT_UNSPECIFIED {
			return fmt.Errorf("platformk8s/clidefinitions: oauth subject summary value_format is unspecified for %q %q", pkg.GetCliId(), fieldID)
		}
		switch field.GetSource() {
		case supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_TOKEN_RESPONSE,
			supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_ID_TOKEN_CLAIMS:
			if strings.TrimSpace(field.GetJsonPointer()) == "" {
				return fmt.Errorf("platformk8s/clidefinitions: oauth subject summary json_pointer is empty for %q %q", pkg.GetCliId(), fieldID)
			}
			if strings.TrimSpace(field.GetMaterialKey()) != "" {
				return fmt.Errorf("platformk8s/clidefinitions: oauth subject summary material_key must be empty for %q %q", pkg.GetCliId(), fieldID)
			}
		case supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_CREDENTIAL_MATERIAL:
			if strings.TrimSpace(field.GetMaterialKey()) == "" {
				return fmt.Errorf("platformk8s/clidefinitions: oauth subject summary material_key is empty for %q %q", pkg.GetCliId(), fieldID)
			}
			if strings.TrimSpace(field.GetJsonPointer()) != "" {
				return fmt.Errorf("platformk8s/clidefinitions: oauth subject summary json_pointer must be empty for %q %q", pkg.GetCliId(), fieldID)
			}
		default:
			if strings.TrimSpace(field.GetJsonPointer()) != "" {
				return fmt.Errorf("platformk8s/clidefinitions: oauth subject summary json_pointer must be empty for %q %q", pkg.GetCliId(), fieldID)
			}
			if strings.TrimSpace(field.GetMaterialKey()) != "" {
				return fmt.Errorf("platformk8s/clidefinitions: oauth subject summary material_key must be empty for %q %q", pkg.GetCliId(), fieldID)
			}
		}
	}
	return nil
}
