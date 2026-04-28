package oauth

import platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"

func isTerminalPhase(phase platformv1alpha1.OAuthAuthorizationSessionPhase) bool {
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func removeString(values []string, target string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	return out
}
