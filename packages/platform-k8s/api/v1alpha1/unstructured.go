package v1alpha1

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	KindCredentialDefinitionResource      = "CredentialDefinitionResource"
	KindOAuthAuthorizationSessionResource = "OAuthAuthorizationSessionResource"
	KindAgentSessionResource              = "AgentSessionResource"
	KindAgentRunResource                  = "AgentRunResource"
	KindAgentSessionActionResource        = "AgentSessionActionResource"
)

// UnmarshalSpecProto unmarshals one spec field into one proto message using
// protojson so enum names and numeric values both remain accepted.
func UnmarshalSpecProto(obj *unstructured.Unstructured, field string, out proto.Message) error {
	if obj == nil {
		return fmt.Errorf("platformk8s/api/v1alpha1: resource is nil")
	}
	if out == nil {
		return fmt.Errorf("platformk8s/api/v1alpha1: proto target is nil")
	}
	value, found, err := unstructured.NestedFieldNoCopy(obj.Object, "spec", field)
	if err != nil {
		return fmt.Errorf("platformk8s/api/v1alpha1: read spec.%s: %w", field, err)
	}
	if !found || value == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("platformk8s/api/v1alpha1: marshal spec.%s: %w", field, err)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, out); err != nil {
		return fmt.Errorf("platformk8s/api/v1alpha1: unmarshal spec.%s: %w", field, err)
	}
	return nil
}

// UnmarshalSpecJSON unmarshals one spec field into one plain Go struct.
func UnmarshalSpecJSON[T any](obj *unstructured.Unstructured, field string, out *T) error {
	if obj == nil {
		return fmt.Errorf("platformk8s/api/v1alpha1: resource is nil")
	}
	if out == nil {
		return fmt.Errorf("platformk8s/api/v1alpha1: target is nil")
	}
	value, found, err := unstructured.NestedFieldNoCopy(obj.Object, "spec", field)
	if err != nil {
		return fmt.Errorf("platformk8s/api/v1alpha1: read spec.%s: %w", field, err)
	}
	if !found || value == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("platformk8s/api/v1alpha1: marshal spec.%s: %w", field, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("platformk8s/api/v1alpha1: unmarshal spec.%s: %w", field, err)
	}
	return nil
}
