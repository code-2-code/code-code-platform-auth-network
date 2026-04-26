package v1alpha1

import (
	"encoding/json"
	"fmt"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	agentrunv1 "code-code.internal/go-contract/platform/agent_run/v1"
	agentsessionv1 "code-code.internal/go-contract/platform/agent_session/v1"
	agentsessionactionv1 "code-code.internal/go-contract/platform/agent_session_action/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func marshalSpecProto(field string, message proto.Message) ([]byte, error) {
	out := map[string]json.RawMessage{}
	if message != nil {
		raw, err := protojson.MarshalOptions{UseProtoNames: false}.Marshal(message)
		if err != nil {
			return nil, fmt.Errorf("platformk8s/api/v1alpha1: marshal spec.%s: %w", field, err)
		}
		out[field] = raw
	}
	return json.Marshal(out)
}

func unmarshalSpecProto(data []byte, field string, message proto.Message) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	value := raw[field]
	if len(value) == 0 || string(value) == "null" {
		return nil
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(value, message); err != nil {
		return fmt.Errorf("platformk8s/api/v1alpha1: unmarshal spec.%s: %w", field, err)
	}
	return nil
}

func (s CredentialDefinitionResourceSpec) MarshalJSON() ([]byte, error) {
	out := map[string]any{}
	if s.Definition != nil {
		raw, err := protojson.MarshalOptions{UseProtoNames: false}.Marshal(s.Definition)
		if err != nil {
			return nil, fmt.Errorf("platformk8s/api/v1alpha1: marshal spec.definition: %w", err)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		out["definition"] = value
	}
	if s.SecretSource != nil {
		out["secretSource"] = s.SecretSource
	}
	return json.Marshal(out)
}

func (s *CredentialDefinitionResourceSpec) UnmarshalJSON(data []byte) error {
	if s == nil {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	definition := &credentialv1.CredentialDefinition{}
	if value := raw["definition"]; len(value) > 0 && string(value) != "null" {
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(value, definition); err != nil {
			return fmt.Errorf("platformk8s/api/v1alpha1: unmarshal spec.definition: %w", err)
		}
	}
	s.Definition = definition
	if value := raw["secretSource"]; len(value) > 0 && string(value) != "null" {
		source := &CredentialSecretSource{}
		if err := json.Unmarshal(value, source); err != nil {
			return err
		}
		s.SecretSource = source
	}
	return nil
}

func (s AgentSessionResourceSpec) MarshalJSON() ([]byte, error) {
	return marshalSpecProto("session", s.Session)
}

func (s *AgentSessionResourceSpec) UnmarshalJSON(data []byte) error {
	if s == nil {
		return nil
	}
	session := &agentsessionv1.AgentSessionSpec{}
	if err := unmarshalSpecProto(data, "session", session); err != nil {
		return err
	}
	s.Session = session
	return nil
}

func (s AgentRunResourceSpec) MarshalJSON() ([]byte, error) {
	return marshalSpecProto("run", s.Run)
}

func (s *AgentRunResourceSpec) UnmarshalJSON(data []byte) error {
	if s == nil {
		return nil
	}
	run := &agentrunv1.AgentRunSpec{}
	if err := unmarshalSpecProto(data, "run", run); err != nil {
		return err
	}
	s.Run = run
	return nil
}

func (s AgentSessionActionResourceSpec) MarshalJSON() ([]byte, error) {
	return marshalSpecProto("action", s.Action)
}

func (s *AgentSessionActionResourceSpec) UnmarshalJSON(data []byte) error {
	if s == nil {
		return nil
	}
	action := &agentsessionactionv1.AgentSessionActionSpec{}
	if err := unmarshalSpecProto(data, "action", action); err != nil {
		return err
	}
	s.Action = action
	return nil
}

func (s AgentRunResourceStatus) MarshalJSON() ([]byte, error) {
	alias := agentRunResourceStatusJSON{
		CommonStatusFields: s.CommonStatusFields,
		Phase:              s.Phase,
		Message:            s.Message,
		WorkloadID:         s.WorkloadID,
		ResultSummary:      s.ResultSummary,
		UpdatedAt:          s.UpdatedAt,
	}
	raw, err := json.Marshal(alias)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	prepareJobs, err := marshalAgentRunPrepareJobStatuses(s.PrepareJobs)
	if err != nil {
		return nil, err
	}
	if len(prepareJobs) > 0 {
		out["prepareJobs"] = prepareJobs
	}
	return json.Marshal(out)
}

func (s *AgentRunResourceStatus) UnmarshalJSON(data []byte) error {
	if s == nil {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	alias := &agentRunResourceStatusJSON{}
	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}
	s.CommonStatusFields = alias.CommonStatusFields
	s.Phase = alias.Phase
	s.Message = alias.Message
	s.WorkloadID = alias.WorkloadID
	s.ResultSummary = alias.ResultSummary
	prepareJobs, err := unmarshalAgentRunPrepareJobStatuses(raw["prepareJobs"])
	if err != nil {
		return err
	}
	s.PrepareJobs = prepareJobs
	s.UpdatedAt = alias.UpdatedAt
	return nil
}

type agentRunResourceStatusJSON struct {
	CommonStatusFields `json:",inline"`
	Phase              AgentRunResourcePhase  `json:"phase,omitempty"`
	Message            string                 `json:"message,omitempty"`
	WorkloadID         string                 `json:"workloadId,omitempty"`
	ResultSummary      *AgentRunResultSummary `json:"resultSummary,omitempty"`
	UpdatedAt          *metav1.Time           `json:"updatedAt,omitempty"`
}

func marshalAgentRunPrepareJobStatuses(items []*agentrunv1.AgentRunPrepareJobStatus) ([]any, error) {
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]any, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		raw, err := protojson.MarshalOptions{UseProtoNames: false}.Marshal(item)
		if err != nil {
			return nil, fmt.Errorf("platformk8s/api/v1alpha1: marshal status.prepareJobs: %w", err)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func unmarshalAgentRunPrepareJobStatuses(raw json.RawMessage) ([]*agentrunv1.AgentRunPrepareJobStatus, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, err
	}
	out := make([]*agentrunv1.AgentRunPrepareJobStatus, 0, len(values))
	for index, value := range values {
		item := &agentrunv1.AgentRunPrepareJobStatus{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(value, item); err != nil {
			return nil, fmt.Errorf("platformk8s/api/v1alpha1: unmarshal status.prepareJobs[%d]: %w", index, err)
		}
		out = append(out, item)
	}
	return out, nil
}
