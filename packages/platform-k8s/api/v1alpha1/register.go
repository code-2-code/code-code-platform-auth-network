package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// GroupName identifies platform-owned domain state object payloads.
	GroupName = "platform.code-code.internal"
)

// GroupVersion identifies the object group/version used by platform CRDs.
var GroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

// SchemeBuilder registers platform object types.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme registers platform object types into one scheme.
var AddToScheme = SchemeBuilder.AddToScheme

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(
		GroupVersion,
		&CredentialDefinitionResource{},
		&CredentialDefinitionResourceList{},
		&OAuthAuthorizationSessionResource{},
		&OAuthAuthorizationSessionResourceList{},
		&AgentSessionResource{},
		&AgentSessionResourceList{},
		&AgentRunResource{},
		&AgentRunResourceList{},
		&AgentSessionActionResource{},
		&AgentSessionActionResourceList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
