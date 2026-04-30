package observability

import (
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func conditionGauge(conditions []metav1.Condition, conditionType string) float64 {
	condition := meta.FindStatusCondition(conditions, conditionType)
	if condition == nil {
		return 0
	}
	if condition.Status == metav1.ConditionTrue {
		return 1
	}
	return 0
}

func normalizeFlow(flow platformv1alpha1.OAuthAuthorizationSessionFlow) string {
	switch flow {
	case platformv1alpha1.OAuthAuthorizationSessionFlowCode:
		return "code"
	case platformv1alpha1.OAuthAuthorizationSessionFlowDevice:
		return "device"
	default:
		return strings.ToLower(strings.TrimSpace(string(flow)))
	}
}

func normalizeTerminalPhase(phase platformv1alpha1.OAuthAuthorizationSessionPhase) string {
	return strings.ToLower(strings.TrimSpace(string(phase)))
}

func isTerminalSessionPhase(phase platformv1alpha1.OAuthAuthorizationSessionPhase) bool {
	switch phase {
	case platformv1alpha1.OAuthAuthorizationSessionPhaseSucceeded,
		platformv1alpha1.OAuthAuthorizationSessionPhaseFailed,
		platformv1alpha1.OAuthAuthorizationSessionPhaseExpired,
		platformv1alpha1.OAuthAuthorizationSessionPhaseCanceled:
		return true
	default:
		return false
	}
}

func normalizeFlowFromProto(flow credentialv1.OAuthAuthorizationFlow) string {
	switch flow {
	case credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_CODE:
		return "code"
	case credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_DEVICE:
		return "device"
	default:
		return strings.ToLower(strings.TrimSpace(flow.String()))
	}
}
