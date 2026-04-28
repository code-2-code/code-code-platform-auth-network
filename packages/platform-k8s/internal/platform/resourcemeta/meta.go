package resourcemeta

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const DisplayNameAnnotation = "platform.code-code.internal/display-name"

var nonResourceIDCharsPattern = regexp.MustCompile(`[^a-z0-9-]+`)

func DisplayNameFromObjectMeta(object metav1.Object, fallback string) string {
	if object == nil {
		return fallback
	}
	if displayName := object.GetAnnotations()[DisplayNameAnnotation]; displayName != "" {
		return displayName
	}
	return fallback
}

func SetDisplayNameAnnotation(object metav1.Object, displayName string) {
	if object == nil || displayName == "" {
		return
	}
	annotations := object.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string, 1)
	}
	annotations[DisplayNameAnnotation] = displayName
	object.SetAnnotations(annotations)
}

func EnsureSurfaceID(surfaceID string, displayName string, fallback string) (string, error) {
	return EnsureResourceID(surfaceID, displayName, fallback)
}

func EnsureResourceID(resourceID string, displayName string, fallback string) (string, error) {
	if resourceID != "" {
		return resourceID, nil
	}
	base := slugifyResourceID(displayName)
	if base == "" {
		base = slugifyResourceID(fallback)
	}
	if base == "" {
		base = "provider"
	}
	suffix, err := RandomHex(3)
	if err != nil {
		return "", fmt.Errorf("platformk8s: generate resource id suffix: %w", err)
	}
	return fmt.Sprintf("%s-%s", base, suffix), nil
}

func slugifyResourceID(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	normalized = strings.ReplaceAll(normalized, " ", "-")
	normalized = nonResourceIDCharsPattern.ReplaceAllString(normalized, "-")
	normalized = strings.Trim(normalized, "-")
	normalized = strings.Join(strings.FieldsFunc(normalized, func(r rune) bool {
		return r == '-'
	}), "-")
	return normalized
}

func RandomHex(bytesLen int) (string, error) {
	buffer := make([]byte, bytesLen)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
