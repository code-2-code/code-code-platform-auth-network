package authservice

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"code-code.internal/go-contract/domainerror"
	observabilityv1 "code-code.internal/go-contract/observability/v1"
)

type SessionInputFormResolver interface {
	ResolveSessionInputForm(ctx context.Context, schemaID string) (*observabilityv1.ActiveQueryInputForm, bool, error)
}

func normalizeSessionInputValues(
	form *observabilityv1.ActiveQueryInputForm,
	values map[string]string,
	existing map[string]string,
) (map[string]string, []string, error) {
	if form == nil {
		return trimCredentialValues(values), nil, nil
	}
	fields := map[string]*observabilityv1.ActiveQueryInputField{}
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
		case observabilityv1.ActiveQueryInputPersistence_ACTIVE_QUERY_INPUT_PERSISTENCE_STORED_MATERIAL:
			out[fieldID] = value
		case observabilityv1.ActiveQueryInputPersistence_ACTIVE_QUERY_INPUT_PERSISTENCE_TRANSIENT:
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
	field *observabilityv1.ActiveQueryInputField,
	value string,
) error {
	targetFieldID := strings.TrimSpace(field.GetTargetFieldId())
	switch field.GetTransform() {
	case observabilityv1.ActiveQueryInputValueTransform_ACTIVE_QUERY_INPUT_VALUE_TRANSFORM_MERGE_SET_COOKIE:
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

func sessionInputRequiredKeys(form *observabilityv1.ActiveQueryInputForm) []string {
	required := make([]string, 0, len(form.GetFields()))
	for _, field := range form.GetFields() {
		if field.GetPersistence() != observabilityv1.ActiveQueryInputPersistence_ACTIVE_QUERY_INPUT_PERSISTENCE_STORED_MATERIAL || !field.GetRequired() {
			continue
		}
		if fieldID := strings.TrimSpace(field.GetFieldId()); fieldID != "" {
			required = append(required, fieldID)
		}
	}
	return required
}

func mergeCookieHeader(requestCookie string, responseSetCookie string) string {
	cookies := map[string]string{}
	for _, pair := range strings.Split(requestCookie, ";") {
		applyCookiePair(cookies, pair)
	}
	for _, line := range strings.Split(responseSetCookie, "\n") {
		headerValue := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(headerValue), "set-cookie:") {
			headerValue = strings.TrimSpace(headerValue[len("set-cookie:"):])
		}
		if index := strings.Index(headerValue, ";"); index >= 0 {
			headerValue = headerValue[:index]
		}
		applyCookiePair(cookies, headerValue)
	}
	keys := make([]string, 0, len(cookies))
	for key := range cookies {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, cookies[key]))
	}
	return strings.Join(parts, "; ")
}

func applyCookiePair(cookies map[string]string, pair string) {
	key, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
	if !ok {
		return
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" {
		return
	}
	if value == "" {
		delete(cookies, key)
		return
	}
	cookies[key] = value
}
