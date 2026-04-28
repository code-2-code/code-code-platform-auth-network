package oauth

import (
	"strings"
	"time"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	OAuthSessionFinalizer                    = "oauth.code-code.internal/finalizer"
	OAuthSessionCallbackRecordedAtAnnotation = "oauth.code-code.internal/callback-recorded-at"
	OAuthSessionRetainUntilAnnotation        = "oauth.code-code.internal/retain-until"

	ConditionOAuthAccepted           = "Accepted"
	ConditionOAuthAuthorizationReady = "AuthorizationReady"
	ConditionOAuthCompleted          = "Completed"
)

func sessionStateFromResource(resource *platformv1alpha1.OAuthAuthorizationSessionResource) *credentialv1.OAuthAuthorizationSessionState {
	if resource == nil {
		return nil
	}
	return &credentialv1.OAuthAuthorizationSessionState{
		Generation: resource.Generation,
		Spec: &credentialv1.OAuthAuthorizationSessionSpec{
			SessionId:           resource.Spec.SessionID,
			CliId:               resource.Spec.CliID,
			Flow:                toProtoFlow(resource.Spec.Flow),
			CallbackMode:        toProtoCallbackMode(resource.Spec.CallbackMode),
			ProviderRedirectUri: resource.Spec.ProviderRedirectURI,
			TargetCredentialId:  resource.Spec.TargetCredentialID,
			TargetDisplayName:   resource.Spec.TargetDisplayName,
		},
		Status: &credentialv1.OAuthAuthorizationSessionStatus{
			Phase:               toProtoPhase(resource.Status.Phase),
			AuthorizationUrl:    resource.Status.AuthorizationURL,
			UserCode:            resource.Status.UserCode,
			PollIntervalSeconds: resource.Status.PollIntervalSeconds,
			ExpiresAt:           toProtoTimestamp(resource.Status.ExpiresAt),
			ImportedCredential:  toProtoImportedCredential(resource.Status.ImportedCredential),
			ObservedGeneration:  resource.Status.ObservedGeneration,
			Conditions:          toProtoConditions(resource.Status.Conditions),
			Message:             resource.Status.Message,
			UpdatedAt:           toProtoTimestamp(resource.Status.UpdatedAt),
		},
	}
}

func toProtoFlow(flow platformv1alpha1.OAuthAuthorizationSessionFlow) credentialv1.OAuthAuthorizationFlow {
	switch flow {
	case platformv1alpha1.OAuthAuthorizationSessionFlowCode:
		return credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_CODE
	case platformv1alpha1.OAuthAuthorizationSessionFlowDevice:
		return credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_DEVICE
	default:
		return credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_UNSPECIFIED
	}
}

func fromProtoFlow(flow credentialv1.OAuthAuthorizationFlow) platformv1alpha1.OAuthAuthorizationSessionFlow {
	switch flow {
	case credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_CODE:
		return platformv1alpha1.OAuthAuthorizationSessionFlowCode
	case credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_DEVICE:
		return platformv1alpha1.OAuthAuthorizationSessionFlowDevice
	default:
		return ""
	}
}

func toProtoCallbackMode(mode platformv1alpha1.OAuthAuthorizationSessionCallbackMode) credentialv1.OAuthCallbackMode {
	switch mode {
	case platformv1alpha1.OAuthAuthorizationSessionCallbackModeHostedCallback:
		return credentialv1.OAuthCallbackMode_O_AUTH_CALLBACK_MODE_HOSTED_CALLBACK
	case platformv1alpha1.OAuthAuthorizationSessionCallbackModeLocalhostRelay:
		return credentialv1.OAuthCallbackMode_O_AUTH_CALLBACK_MODE_LOCALHOST_RELAY
	default:
		return credentialv1.OAuthCallbackMode_O_AUTH_CALLBACK_MODE_UNSPECIFIED
	}
}

func fromProtoCallbackMode(mode credentialv1.OAuthCallbackMode) platformv1alpha1.OAuthAuthorizationSessionCallbackMode {
	switch mode {
	case credentialv1.OAuthCallbackMode_O_AUTH_CALLBACK_MODE_HOSTED_CALLBACK:
		return platformv1alpha1.OAuthAuthorizationSessionCallbackModeHostedCallback
	case credentialv1.OAuthCallbackMode_O_AUTH_CALLBACK_MODE_LOCALHOST_RELAY:
		return platformv1alpha1.OAuthAuthorizationSessionCallbackModeLocalhostRelay
	default:
		return ""
	}
}

func toProtoPhase(phase platformv1alpha1.OAuthAuthorizationSessionPhase) credentialv1.OAuthAuthorizationPhase {
	switch phase {
	case platformv1alpha1.OAuthAuthorizationSessionPhasePending:
		return credentialv1.OAuthAuthorizationPhase_O_AUTH_AUTHORIZATION_PHASE_PENDING
	case platformv1alpha1.OAuthAuthorizationSessionPhaseAwaitingUser:
		return credentialv1.OAuthAuthorizationPhase_O_AUTH_AUTHORIZATION_PHASE_AWAITING_USER
	case platformv1alpha1.OAuthAuthorizationSessionPhaseProcessing:
		return credentialv1.OAuthAuthorizationPhase_O_AUTH_AUTHORIZATION_PHASE_PROCESSING
	case platformv1alpha1.OAuthAuthorizationSessionPhaseSucceeded:
		return credentialv1.OAuthAuthorizationPhase_O_AUTH_AUTHORIZATION_PHASE_SUCCEEDED
	case platformv1alpha1.OAuthAuthorizationSessionPhaseFailed:
		return credentialv1.OAuthAuthorizationPhase_O_AUTH_AUTHORIZATION_PHASE_FAILED
	case platformv1alpha1.OAuthAuthorizationSessionPhaseExpired:
		return credentialv1.OAuthAuthorizationPhase_O_AUTH_AUTHORIZATION_PHASE_EXPIRED
	case platformv1alpha1.OAuthAuthorizationSessionPhaseCanceled:
		return credentialv1.OAuthAuthorizationPhase_O_AUTH_AUTHORIZATION_PHASE_CANCELED
	default:
		return credentialv1.OAuthAuthorizationPhase_O_AUTH_AUTHORIZATION_PHASE_UNSPECIFIED
	}
}

func toProtoTimestamp(value *metav1.Time) *timestamppb.Timestamp {
	if value == nil || value.IsZero() {
		return nil
	}
	return timestamppb.New(value.UTC())
}

func toProtoImportedCredential(value *platformv1alpha1.ImportedCredentialSummary) *credentialv1.ImportedCredentialSummary {
	if value == nil {
		return nil
	}
	kind := credentialv1.CredentialKind_CREDENTIAL_KIND_UNSPECIFIED
	if parsed, ok := credentialv1.CredentialKind_value[strings.TrimSpace(value.Kind)]; ok {
		kind = credentialv1.CredentialKind(parsed)
	}
	return &credentialv1.ImportedCredentialSummary{
		CredentialId: value.CredentialID,
		DisplayName:  value.DisplayName,
		Kind:         kind,
	}
}

func toProtoConditions(conditions []metav1.Condition) []*credentialv1.OAuthAuthorizationSessionCondition {
	if len(conditions) == 0 {
		return nil
	}
	out := make([]*credentialv1.OAuthAuthorizationSessionCondition, 0, len(conditions))
	for i := range conditions {
		out = append(out, &credentialv1.OAuthAuthorizationSessionCondition{
			Type:               conditions[i].Type,
			Status:             toProtoConditionStatus(conditions[i].Status),
			Reason:             conditions[i].Reason,
			Message:            conditions[i].Message,
			ObservedGeneration: conditions[i].ObservedGeneration,
			LastTransitionTime: timestamppb.New(conditions[i].LastTransitionTime.UTC()),
		})
	}
	return out
}

func toProtoConditionStatus(status metav1.ConditionStatus) credentialv1.OAuthAuthorizationConditionStatus {
	switch status {
	case metav1.ConditionTrue:
		return credentialv1.OAuthAuthorizationConditionStatus_O_AUTH_AUTHORIZATION_CONDITION_STATUS_TRUE
	case metav1.ConditionFalse:
		return credentialv1.OAuthAuthorizationConditionStatus_O_AUTH_AUTHORIZATION_CONDITION_STATUS_FALSE
	default:
		return credentialv1.OAuthAuthorizationConditionStatus_O_AUTH_AUTHORIZATION_CONDITION_STATUS_UNKNOWN
	}
}

func newTerminalAnnotationTime(now time.Time, retention time.Duration) string {
	return now.UTC().Add(retention).Format(time.RFC3339)
}

func parseAnnotationTime(value string) (time.Time, bool) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}
