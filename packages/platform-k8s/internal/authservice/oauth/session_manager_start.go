package oauth

import (
	"context"
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (m *SessionManager) startResource(ctx context.Context, request *credentialv1.OAuthAuthorizationSessionSpec, now metav1.Time) (*platformv1alpha1.OAuthAuthorizationSessionResource, error) {
	cliID := strings.TrimSpace(request.GetCliId())
	oauthSurface := credentialcontract.OAuthCLIID(cliID)
	switch request.GetFlow() {
	case credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_CODE:
		return m.startCodeFlowResource(ctx, request, oauthSurface, cliID, now)
	case credentialv1.OAuthAuthorizationFlow_O_AUTH_AUTHORIZATION_FLOW_DEVICE:
		return m.startDeviceFlowResource(ctx, oauthSurface, cliID, request, now)
	default:
		return nil, errUnsupportedFlow(request.GetFlow())
	}
}

func (m *SessionManager) startCodeFlowResource(ctx context.Context, request *credentialv1.OAuthAuthorizationSessionSpec, oauthSurface credentialcontract.OAuthCLIID, cliID string, now metav1.Time) (*platformv1alpha1.OAuthAuthorizationSessionResource, error) {
	callbackContract, err := m.resolveCodeFlowCallbackContract(ctx, cliID)
	if err != nil {
		return nil, err
	}
	authorizer, err := m.registry.CodeFlowAuthorizer(oauthSurface)
	if err != nil {
		return nil, err
	}
	session, err := authorizer.StartAuthorizationSession(ctx, &credentialcontract.OAuthAuthorizationRequest{
		CliID:               oauthSurface,
		ProviderRedirectURI: callbackContract.ProviderRedirectURI,
	})
	if err != nil {
		return nil, err
	}
	return &platformv1alpha1.OAuthAuthorizationSessionResource{
		TypeMeta: metav1.TypeMeta{
			APIVersion: platformv1alpha1.GroupVersion.String(),
			Kind:       platformv1alpha1.KindOAuthAuthorizationSessionResource,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       session.SessionID,
			Namespace:  m.namespace,
			Finalizers: []string{OAuthSessionFinalizer},
		},
		Spec: platformv1alpha1.OAuthAuthorizationSessionSpec{
			SessionID:           session.SessionID,
			CliID:               cliID,
			Flow:                platformv1alpha1.OAuthAuthorizationSessionFlowCode,
			CallbackMode:        fromProtoCallbackMode(callbackContract.Mode),
			ProviderRedirectURI: callbackContract.ProviderRedirectURI,
			TargetCredentialID:  strings.TrimSpace(request.GetTargetCredentialId()),
			TargetDisplayName:   strings.TrimSpace(request.GetTargetDisplayName()),
		},
		Status: platformv1alpha1.OAuthAuthorizationSessionStatus{
			CommonStatusFields: platformv1alpha1.CommonStatusFields{
				Conditions: []metav1.Condition{{
					Type:               ConditionOAuthAccepted,
					Status:             metav1.ConditionTrue,
					Reason:             "Accepted",
					Message:            "OAuth session accepted.",
					ObservedGeneration: 1,
					LastTransitionTime: now,
				}, {
					Type:               ConditionOAuthAuthorizationReady,
					Status:             metav1.ConditionTrue,
					Reason:             "AuthorizationReady",
					Message:            "Authorization URL is ready.",
					ObservedGeneration: 1,
					LastTransitionTime: now,
				}},
			},
			Phase:            platformv1alpha1.OAuthAuthorizationSessionPhaseAwaitingUser,
			AuthorizationURL: session.AuthorizationURL,
			ExpiresAt:        toMetaTime(session.ExpiresAt),
			UpdatedAt:        &now,
		},
	}, nil
}

func (m *SessionManager) startDeviceFlowResource(ctx context.Context, oauthSurface credentialcontract.OAuthCLIID, cliID string, request *credentialv1.OAuthAuthorizationSessionSpec, now metav1.Time) (*platformv1alpha1.OAuthAuthorizationSessionResource, error) {
	authorizer, err := m.registry.DeviceFlowAuthorizer(oauthSurface)
	if err != nil {
		return nil, err
	}
	session, err := authorizer.StartAuthorizationSession(ctx, &credentialcontract.DeviceAuthorizationRequest{})
	if err != nil {
		return nil, err
	}
	return &platformv1alpha1.OAuthAuthorizationSessionResource{
		TypeMeta: metav1.TypeMeta{
			APIVersion: platformv1alpha1.GroupVersion.String(),
			Kind:       platformv1alpha1.KindOAuthAuthorizationSessionResource,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       session.SessionID,
			Namespace:  m.namespace,
			Finalizers: []string{OAuthSessionFinalizer},
		},
		Spec: platformv1alpha1.OAuthAuthorizationSessionSpec{
			SessionID:          session.SessionID,
			CliID:              cliID,
			Flow:               platformv1alpha1.OAuthAuthorizationSessionFlowDevice,
			TargetCredentialID: strings.TrimSpace(request.GetTargetCredentialId()),
			TargetDisplayName:  strings.TrimSpace(request.GetTargetDisplayName()),
		},
		Status: platformv1alpha1.OAuthAuthorizationSessionStatus{
			CommonStatusFields: platformv1alpha1.CommonStatusFields{
				Conditions: []metav1.Condition{{
					Type:               ConditionOAuthAccepted,
					Status:             metav1.ConditionTrue,
					Reason:             "Accepted",
					Message:            "OAuth session accepted.",
					ObservedGeneration: 1,
					LastTransitionTime: now,
				}, {
					Type:               ConditionOAuthAuthorizationReady,
					Status:             metav1.ConditionTrue,
					Reason:             "AuthorizationReady",
					Message:            "Device authorization session is ready.",
					ObservedGeneration: 1,
					LastTransitionTime: now,
				}},
			},
			Phase:               platformv1alpha1.OAuthAuthorizationSessionPhasePending,
			AuthorizationURL:    session.AuthorizationURL,
			UserCode:            session.UserCode,
			PollIntervalSeconds: session.PollIntervalSeconds,
			ExpiresAt:           toMetaTime(session.ExpiresAt),
			UpdatedAt:           &now,
		},
	}, nil
}
