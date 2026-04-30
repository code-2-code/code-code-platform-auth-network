package oauth

import (
	"fmt"
	"strings"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
)

type SubjectSummaryField struct {
	FieldID string
	Label   string
	Value   string
}

type SubjectSummaryMaterialValueReader func(materialKey string) (string, error)

func ResolveCredentialSubjectSummary(
	cli *supportv1.CLI,
	artifact *credentialcontract.OAuthArtifact,
	readMaterialValue SubjectSummaryMaterialValueReader,
) ([]SubjectSummaryField, error) {
	if cli == nil || cli.GetOauth() == nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: cli oauth support is nil")
	}
	if artifact == nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: oauth artifact is nil")
	}
	fields := make([]SubjectSummaryField, 0, len(cli.GetOauth().GetSubjectSummaryFields()))
	for _, declared := range cli.GetOauth().GetSubjectSummaryFields() {
		if declared == nil {
			continue
		}
		value, err := resolveSubjectSummaryValue(declared, artifact, readMaterialValue)
		if err != nil {
			return nil, err
		}
		if value == "" {
			continue
		}
		fields = append(fields, SubjectSummaryField{
			FieldID: strings.TrimSpace(declared.GetFieldId()),
			Label:   strings.TrimSpace(declared.GetLabel()),
			Value:   formatSubjectSummaryValue(declared.GetValueFormat(), value),
		})
	}
	return fields, nil
}

func resolveSubjectSummaryValue(
	field *supportv1.CredentialSubjectSummaryField,
	artifact *credentialcontract.OAuthArtifact,
	readMaterialValue SubjectSummaryMaterialValueReader,
) (string, error) {
	switch field.GetSource() {
	case supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_ARTIFACT_SUBJECT_EMAIL:
		return strings.TrimSpace(artifact.AccountEmail), nil
	case supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_ARTIFACT_SUBJECT_ID:
		return strings.TrimSpace(artifact.AccountID), nil
	case supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_TOKEN_RESPONSE:
		return projectionValue(
			supportv1.OAuthArtifactSource_O_AUTH_ARTIFACT_SOURCE_TOKEN_RESPONSE,
			field.GetJsonPointer(),
			artifact,
		)
	case supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_ID_TOKEN_CLAIMS:
		return projectionValue(
			supportv1.OAuthArtifactSource_O_AUTH_ARTIFACT_SOURCE_ID_TOKEN_CLAIMS,
			field.GetJsonPointer(),
			artifact,
		)
	case supportv1.CredentialSubjectSummarySource_CREDENTIAL_SUBJECT_SUMMARY_SOURCE_CREDENTIAL_MATERIAL:
		if readMaterialValue == nil {
			return "", fmt.Errorf("platformk8s/clidefinitions: oauth subject summary material reader is nil")
		}
		value, err := readMaterialValue(field.GetMaterialKey())
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(value), nil
	default:
		return "", fmt.Errorf("platformk8s/clidefinitions: oauth subject summary source is unspecified")
	}
}

func formatSubjectSummaryValue(format supportv1.CredentialSubjectSummaryValueFormat, value string) string {
	switch format {
	case supportv1.CredentialSubjectSummaryValueFormat_CREDENTIAL_SUBJECT_SUMMARY_VALUE_FORMAT_MASK_EMAIL:
		return maskEmail(value)
	default:
		return strings.TrimSpace(value)
	}
}

func maskEmail(value string) string {
	value = strings.TrimSpace(value)
	parts := strings.SplitN(value, "@", 2)
	if len(parts) != 2 {
		return value
	}
	local, domain := parts[0], parts[1]
	switch len(local) {
	case 0:
		return "***@" + domain
	case 1:
		return local[:1] + "***@" + domain
	default:
		return local[:1] + "***" + local[len(local)-1:] + "@" + domain
	}
}
