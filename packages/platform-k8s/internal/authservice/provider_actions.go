package authservice

import (
	"context"
	"slices"
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	clioauth "code-code.internal/platform-k8s/internal/supportservice/clidefinitions/oauth"
)

func (s *Server) GetCredentialSubjectSummary(ctx context.Context, request *authv1.GetCredentialSubjectSummaryRequest) (*authv1.GetCredentialSubjectSummaryResponse, error) {
	return &authv1.GetCredentialSubjectSummaryResponse{Fields: s.resolveCredentialSubjectSummary(ctx, request.GetCredentialId())}, nil
}

func (s *Server) resolveCredentialSubjectSummary(ctx context.Context, credentialID string) []*managementv1.CredentialSubjectSummaryFieldView {
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return nil
	}
	definition, err := s.credentialWriter.ReadDefinition(ctx, credentialID)
	if err != nil || definition == nil {
		return nil
	}
	switch definition.GetKind() {
	case credentialv1.CredentialKind_CREDENTIAL_KIND_OAUTH:
		return s.resolveCLIOAuthSummary(ctx, credentialID, strings.TrimSpace(definition.GetOauthMetadata().GetCliId()))
	case credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION:
		return s.resolveSessionCredentialSummary(ctx, credentialID)
	default:
		return nil
	}
}

func (s *Server) resolveCLIOAuthSummary(ctx context.Context, credentialID string, cliID string) []*managementv1.CredentialSubjectSummaryFieldView {
	credentialID = strings.TrimSpace(credentialID)
	cliID = strings.TrimSpace(cliID)
	if credentialID == "" || cliID == "" {
		return nil
	}
	cli, err := s.oauthSessions.runtime.cliSupport.Get(ctx, cliID)
	if err != nil {
		return nil
	}
	artifact, err := s.credentialWriter.ReadOAuthArtifact(ctx, credentialID)
	if err != nil {
		return nil
	}
	fields, err := clioauth.ResolveCredentialSubjectSummary(cli, artifact, func(materialKey string) (string, error) {
		return s.credentialWriter.ReadMaterialValue(ctx, credentialID, materialKey)
	})
	if err != nil {
		return nil
	}
	items := make([]*managementv1.CredentialSubjectSummaryFieldView, 0, len(fields))
	for _, field := range fields {
		if strings.TrimSpace(field.Value) == "" {
			continue
		}
		items = append(items, &managementv1.CredentialSubjectSummaryFieldView{
			FieldId: field.FieldID,
			Label:   field.Label,
			Value:   field.Value,
		})
	}
	return items
}

func (s *Server) resolveSessionCredentialSummary(ctx context.Context, credentialID string) []*managementv1.CredentialSubjectSummaryFieldView {
	values, err := s.credentialWriter.ReadMaterialValues(ctx, credentialID)
	if err != nil || len(values) == 0 {
		return nil
	}
	keys := sortedStringKeys(values)
	items := make([]*managementv1.CredentialSubjectSummaryFieldView, 0, len(keys))
	for _, key := range keys {
		fieldID := strings.TrimSpace(key)
		value := strings.TrimSpace(values[key])
		if value == "" || isSensitiveSummaryField(fieldID) {
			continue
		}
		items = append(items, &managementv1.CredentialSubjectSummaryFieldView{
			FieldId: fieldID,
			Label:   summaryFieldLabel(fieldID),
			Value:   value,
		})
	}
	return items
}

func sortedStringKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}

func isSensitiveSummaryField(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return true
	}
	switch normalized {
	case "auth", "authorization", "bearer", "cookie", "csrf", "password", "secret":
		return true
	}
	for _, marker := range []string{"cookie", "password", "secret", "token"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func summaryFieldLabel(key string) string {
	parts := strings.FieldsFunc(strings.TrimSpace(key), func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	for i, part := range parts {
		parts[i] = summaryLabelWord(part)
	}
	return strings.Join(parts, " ")
}

func summaryLabelWord(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch lower {
	case "api", "id", "url", "http", "https", "oauth", "jwt", "csrf":
		return strings.ToUpper(lower)
	default:
		if lower == "" {
			return ""
		}
		return strings.ToUpper(lower[:1]) + lower[1:]
	}
}
