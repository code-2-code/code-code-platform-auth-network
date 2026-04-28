package v1alpha1

import (
	credentialv1 "code-code.internal/go-contract/credential/v1"
	agentrunv1 "code-code.internal/go-contract/platform/agent_run/v1"
	agentsessionv1 "code-code.internal/go-contract/platform/agent_session/v1"
	agentsessionactionv1 "code-code.internal/go-contract/platform/agent_session_action/v1"
	"google.golang.org/protobuf/proto"
)

func (in *CredentialDefinitionResourceSpec) DeepCopyInto(out *CredentialDefinitionResourceSpec) {
	*out = *in
	out.Definition = cloneCredentialDefinition(in.Definition)
}

func (in *CredentialDefinitionResourceSpec) DeepCopy() *CredentialDefinitionResourceSpec {
	if in == nil {
		return nil
	}
	out := new(CredentialDefinitionResourceSpec)
	in.DeepCopyInto(out)
	return out
}

func (in *AgentSessionResourceSpec) DeepCopyInto(out *AgentSessionResourceSpec) {
	*out = *in
	out.Session = cloneAgentSessionSpec(in.Session)
}

func (in *AgentSessionResourceSpec) DeepCopy() *AgentSessionResourceSpec {
	if in == nil {
		return nil
	}
	out := new(AgentSessionResourceSpec)
	in.DeepCopyInto(out)
	return out
}

func (in *AgentRunResourceSpec) DeepCopyInto(out *AgentRunResourceSpec) {
	*out = *in
	out.Run = cloneAgentRunSpec(in.Run)
}

func (in *AgentRunResourceSpec) DeepCopy() *AgentRunResourceSpec {
	if in == nil {
		return nil
	}
	out := new(AgentRunResourceSpec)
	in.DeepCopyInto(out)
	return out
}

func (in *AgentRunResourceStatus) DeepCopyInto(out *AgentRunResourceStatus) {
	*out = *in
	in.CommonStatusFields.DeepCopyInto(&out.CommonStatusFields)
	if in.ResultSummary != nil {
		out.ResultSummary = &AgentRunResultSummary{
			Status:       in.ResultSummary.Status,
			ErrorCode:    in.ResultSummary.ErrorCode,
			ErrorMessage: in.ResultSummary.ErrorMessage,
			Retryable:    in.ResultSummary.Retryable,
		}
	}
	if in.PrepareJobs != nil {
		out.PrepareJobs = make([]*agentrunv1.AgentRunPrepareJobStatus, 0, len(in.PrepareJobs))
		for _, item := range in.PrepareJobs {
			if item != nil {
				out.PrepareJobs = append(out.PrepareJobs, proto.Clone(item).(*agentrunv1.AgentRunPrepareJobStatus))
			}
		}
	}
	if in.UpdatedAt != nil {
		out.UpdatedAt = in.UpdatedAt.DeepCopy()
	}
}

func (in *AgentRunResourceStatus) DeepCopy() *AgentRunResourceStatus {
	if in == nil {
		return nil
	}
	out := new(AgentRunResourceStatus)
	in.DeepCopyInto(out)
	return out
}

func (in *AgentSessionActionResourceSpec) DeepCopyInto(out *AgentSessionActionResourceSpec) {
	*out = *in
	out.Action = cloneAgentSessionActionSpec(in.Action)
}

func (in *AgentSessionActionResourceSpec) DeepCopy() *AgentSessionActionResourceSpec {
	if in == nil {
		return nil
	}
	out := new(AgentSessionActionResourceSpec)
	in.DeepCopyInto(out)
	return out
}

func cloneCredentialDefinition(in *credentialv1.CredentialDefinition) *credentialv1.CredentialDefinition {
	if in == nil {
		return nil
	}
	return proto.Clone(in).(*credentialv1.CredentialDefinition)
}

func cloneAgentSessionSpec(in *agentsessionv1.AgentSessionSpec) *agentsessionv1.AgentSessionSpec {
	if in == nil {
		return nil
	}
	return proto.Clone(in).(*agentsessionv1.AgentSessionSpec)
}

func cloneAgentRunSpec(in *agentrunv1.AgentRunSpec) *agentrunv1.AgentRunSpec {
	if in == nil {
		return nil
	}
	return proto.Clone(in).(*agentrunv1.AgentRunSpec)
}

func cloneAgentSessionActionSpec(in *agentsessionactionv1.AgentSessionActionSpec) *agentsessionactionv1.AgentSessionActionSpec {
	if in == nil {
		return nil
	}
	return proto.Clone(in).(*agentsessionactionv1.AgentSessionActionSpec)
}
