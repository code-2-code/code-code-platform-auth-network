package authservice

import (
	"context"
	"strings"

	"code-code.internal/go-contract/domainerror"
	observabilityv1 "code-code.internal/go-contract/observability/v1"
	"code-code.internal/platform-k8s/internal/sessioncookie"
)

type SessionInputFormResolver interface {
	ResolveSessionInputForm(ctx context.Context, schemaID string) (*observabilityv1.QuotaQueryInputForm, bool, error)
}

func normalizeSessionInputValues(
	form *observabilityv1.QuotaQueryInputForm,
	values map[string]string,
	existing map[string]string,
) (map[string]string, []string, error) {
	if form == nil {
		return trimCredentialValues(values), nil, nil
	}
	fields := map[string]*observabilityv1.QuotaQueryInputField{}
	for _, field := range form.GetFields() {
		if fieldID := strings.TrimSpace(field.GetFieldId()); fieldID != "" {
			fields[fieldID] = field
		}
	}
	for key, value := range values {
		key = strings.TrimSpace(key)
		if key == "" || strings.TrimSpace(value) == "" {
			continue
		}
		if _, ok := fields[key]; !ok {
			return nil, nil, domainerror.NewValidation("platformk8s/authservice: session input field %q is not declared by schema %q", key, form.GetSchemaId())
		}
	}

	out := map[string]string{}
	for _, field := range form.GetFields() {
		fieldID := strings.TrimSpace(field.GetFieldId())
		value := strings.TrimSpace(values[fieldID])
		if value == "" {
			continue
		}
		switch field.GetPersistence() {
		case observabilityv1.QuotaQueryInputPersistence_QUOTA_QUERY_INPUT_PERSISTENCE_STORED_MATERIAL:
			out[fieldID] = value
		case observabilityv1.QuotaQueryInputPersistence_QUOTA_QUERY_INPUT_PERSISTENCE_TRANSIENT:
			if err := applyTransientSessionInput(out, values, existing, field, value); err != nil {
				return nil, nil, err
			}
		}
	}
	if len(out) == 0 {
		return nil, nil, domainerror.NewValidation("platformk8s/authservice: session input values are required")
	}
	return out, sessionInputRequiredKeys(form), nil
}

func applyTransientSessionInput(
	out map[string]string,
	values map[string]string,
	existing map[string]string,
	field *observabilityv1.QuotaQueryInputField,
	value string,
) error {
	targetFieldID := strings.TrimSpace(field.GetTargetFieldId())
	switch field.GetTransform() {
	case observabilityv1.QuotaQueryInputValueTransform_QUOTA_QUERY_INPUT_VALUE_TRANSFORM_MERGE_SET_COOKIE:
		base := strings.TrimSpace(out[targetFieldID])
		if base == "" {
			base = strings.TrimSpace(values[targetFieldID])
		}
		if base == "" {
			base = strings.TrimSpace(existing[targetFieldID])
		}
		if base == "" {
			return domainerror.NewValidation(
				"platformk8s/authservice: session input field %q requires target field %q in the same submission or existing material",
				field.GetFieldId(),
				targetFieldID,
			)
		}
		if merged := mergeCookieHeader(base, value); merged != "" {
			out[targetFieldID] = merged
		}
		return nil
	default:
		return domainerror.NewValidation(
			"platformk8s/authservice: unsupported session input transform %s for field %q",
			field.GetTransform().String(),
			field.GetFieldId(),
		)
	}
}

func sessionInputRequiredKeys(form *observabilityv1.QuotaQueryInputForm) []string {
	required := make([]string, 0, len(form.GetFields()))
	for _, field := range form.GetFields() {
		if field.GetPersistence() != observabilityv1.QuotaQueryInputPersistence_QUOTA_QUERY_INPUT_PERSISTENCE_STORED_MATERIAL || !field.GetRequired() {
			continue
		}
		if fieldID := strings.TrimSpace(field.GetFieldId()); fieldID != "" {
			required = append(required, fieldID)
		}
	}
	return required
}

func mergeCookieHeader(requestCookie string, responseSetCookie string) string {
	return sessioncookie.Merge(requestCookie, responseSetCookie)
}
