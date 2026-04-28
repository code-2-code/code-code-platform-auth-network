package v1alpha1

import (
	credentialv1 "code-code.internal/go-contract/credential/v1"
	agentrunv1 "code-code.internal/go-contract/platform/agent_run/v1"
	agentsessionv1 "code-code.internal/go-contract/platform/agent_session/v1"
	agentsessionactionv1 "code-code.internal/go-contract/platform/agent_session_action/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CommonStatusFields are controller-owned observation fields shared by
// resources with an active reconcile loop.
type CommonStatusFields struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// CredentialDefinitionResource stores one credential definition in externalized
// platform state. Credential material is owned by auth-service storage.
type CredentialDefinitionResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CredentialDefinitionResourceSpec   `json:"spec,omitempty"`
	Status            CredentialDefinitionResourceStatus `json:"status,omitempty"`
}

// CredentialDefinitionResourceSpec stores one credential definition payload.
type CredentialDefinitionResourceSpec struct {
	Definition *credentialv1.CredentialDefinition `json:"definition,omitempty"`
}

// CredentialDefinitionResourceStatus stores controller-owned credential
// lifecycle observations.
type CredentialDefinitionResourceStatus struct {
	CommonStatusFields `json:",inline"`
	OAuth              *CredentialOAuthStatus `json:"oauth,omitempty"`
}

// CredentialOAuthStatus stores observed OAuth token lifecycle state.
type CredentialOAuthStatus struct {
	CliID                string       `json:"cliId,omitempty"`
	CredentialGeneration int64        `json:"credentialGeneration,omitempty"`
	NextRefreshAfter     *metav1.Time `json:"nextRefreshAfter,omitempty"`
	LastRefreshedAt      *metav1.Time `json:"lastRefreshedAt,omitempty"`
	AccountEmail         string       `json:"accountEmail,omitempty"`
}

// CredentialDefinitionResourceList lists credential definition resources.
type CredentialDefinitionResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CredentialDefinitionResource `json:"items"`
}

// OAuthAuthorizationSessionFlow identifies the supported OAuth authorization flow.
type OAuthAuthorizationSessionFlow string

const (
	OAuthAuthorizationSessionFlowCode   OAuthAuthorizationSessionFlow = "CODE"
	OAuthAuthorizationSessionFlowDevice OAuthAuthorizationSessionFlow = "DEVICE"
)

// OAuthAuthorizationSessionCallbackMode identifies how one code-flow callback
// is delivered back into the platform.
type OAuthAuthorizationSessionCallbackMode string

const (
	OAuthAuthorizationSessionCallbackModeHostedCallback OAuthAuthorizationSessionCallbackMode = "HOSTED_CALLBACK"
	OAuthAuthorizationSessionCallbackModeLocalhostRelay OAuthAuthorizationSessionCallbackMode = "LOCALHOST_RELAY"
)

// OAuthAuthorizationSessionPhase identifies the observed OAuth session phase.
type OAuthAuthorizationSessionPhase string

const (
	OAuthAuthorizationSessionPhasePending      OAuthAuthorizationSessionPhase = "PENDING"
	OAuthAuthorizationSessionPhaseAwaitingUser OAuthAuthorizationSessionPhase = "AWAITING_USER"
	OAuthAuthorizationSessionPhaseProcessing   OAuthAuthorizationSessionPhase = "PROCESSING"
	OAuthAuthorizationSessionPhaseSucceeded    OAuthAuthorizationSessionPhase = "SUCCEEDED"
	OAuthAuthorizationSessionPhaseFailed       OAuthAuthorizationSessionPhase = "FAILED"
	OAuthAuthorizationSessionPhaseExpired      OAuthAuthorizationSessionPhase = "EXPIRED"
	OAuthAuthorizationSessionPhaseCanceled     OAuthAuthorizationSessionPhase = "CANCELED"
)

// ImportedCredentialSummary stores the imported credential summary for one completed OAuth session.
type ImportedCredentialSummary struct {
	CredentialID string `json:"credentialId,omitempty"`
	DisplayName  string `json:"displayName,omitempty"`
	Kind         string `json:"kind,omitempty"`
}

// OAuthAuthorizationSessionResource stores one OAuth authorization session in externalized platform state.
type OAuthAuthorizationSessionResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OAuthAuthorizationSessionSpec   `json:"spec,omitempty"`
	Status            OAuthAuthorizationSessionStatus `json:"status,omitempty"`
}

// OAuthAuthorizationSessionSpec stores one OAuth authorization session desired state.
type OAuthAuthorizationSessionSpec struct {
	SessionID           string                                `json:"sessionId,omitempty"`
	CliID               string                                `json:"cliId,omitempty"`
	Flow                OAuthAuthorizationSessionFlow         `json:"flow,omitempty"`
	CallbackMode        OAuthAuthorizationSessionCallbackMode `json:"callbackMode,omitempty"`
	ProviderRedirectURI string                                `json:"providerRedirectUri,omitempty"`
	TargetCredentialID  string                                `json:"targetCredentialId,omitempty"`
	TargetDisplayName   string                                `json:"targetDisplayName,omitempty"`
}

// OAuthAuthorizationSessionStatus stores controller-owned OAuth authorization session observation.
type OAuthAuthorizationSessionStatus struct {
	CommonStatusFields  `json:",inline"`
	Phase               OAuthAuthorizationSessionPhase `json:"phase,omitempty"`
	AuthorizationURL    string                         `json:"authorizationUrl,omitempty"`
	UserCode            string                         `json:"userCode,omitempty"`
	PollIntervalSeconds int32                          `json:"pollIntervalSeconds,omitempty"`
	ExpiresAt           *metav1.Time                   `json:"expiresAt,omitempty"`
	ImportedCredential  *ImportedCredentialSummary     `json:"importedCredential,omitempty"`
	Message             string                         `json:"message,omitempty"`
	UpdatedAt           *metav1.Time                   `json:"updatedAt,omitempty"`
}

// OAuthAuthorizationSessionResourceList lists OAuth authorization sessions.
type OAuthAuthorizationSessionResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OAuthAuthorizationSessionResource `json:"items"`
}

// AgentSessionResourcePhase identifies the observed session phase.
type AgentSessionResourcePhase string

const (
	AgentSessionResourcePhasePending AgentSessionResourcePhase = "PENDING"
	AgentSessionResourcePhaseReady   AgentSessionResourcePhase = "READY"
	AgentSessionResourcePhaseRunning AgentSessionResourcePhase = "RUNNING"
	AgentSessionResourcePhaseFailed  AgentSessionResourcePhase = "FAILED"
)

// AgentRunResourcePhase identifies the observed run phase.
type AgentRunResourcePhase string

const (
	AgentRunResourcePhasePending   AgentRunResourcePhase = "PENDING"
	AgentRunResourcePhaseScheduled AgentRunResourcePhase = "SCHEDULED"
	AgentRunResourcePhaseRunning   AgentRunResourcePhase = "RUNNING"
	AgentRunResourcePhaseSucceeded AgentRunResourcePhase = "SUCCEEDED"
	AgentRunResourcePhaseFailed    AgentRunResourcePhase = "FAILED"
	AgentRunResourcePhaseCanceled  AgentRunResourcePhase = "CANCELED"
)

// AgentSessionActionResourcePhase identifies the observed action phase.
type AgentSessionActionResourcePhase string

const (
	AgentSessionActionResourcePhasePending   AgentSessionActionResourcePhase = "PENDING"
	AgentSessionActionResourcePhaseRunning   AgentSessionActionResourcePhase = "RUNNING"
	AgentSessionActionResourcePhaseSucceeded AgentSessionActionResourcePhase = "SUCCEEDED"
	AgentSessionActionResourcePhaseFailed    AgentSessionActionResourcePhase = "FAILED"
	AgentSessionActionResourcePhaseCanceled  AgentSessionActionResourcePhase = "CANCELED"
)

// AgentSessionActionResourceFailureClass identifies the current retry / failure
// class observed for one action.
type AgentSessionActionResourceFailureClass string

const (
	AgentSessionActionResourceFailureClassBlocked     AgentSessionActionResourceFailureClass = "BLOCKED"
	AgentSessionActionResourceFailureClassTransient   AgentSessionActionResourceFailureClass = "TRANSIENT"
	AgentSessionActionResourceFailureClassPermanent   AgentSessionActionResourceFailureClass = "PERMANENT"
	AgentSessionActionResourceFailureClassManualRetry AgentSessionActionResourceFailureClass = "MANUAL_RETRY"
)

// AgentSessionResource stores one internal agentSession state object.
type AgentSessionResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AgentSessionResourceSpec   `json:"spec,omitempty"`
	Status            AgentSessionResourceStatus `json:"status,omitempty"`
}

// AgentSessionResourceSpec stores one desired agentSession payload.
type AgentSessionResourceSpec struct {
	Session *agentsessionv1.AgentSessionSpec `json:"session,omitempty"`
}

// AgentSessionResourceStatus stores controller-owned agentSession observation.
type AgentSessionResourceStatus struct {
	CommonStatusFields       `json:",inline"`
	Phase                    AgentSessionResourcePhase `json:"phase,omitempty"`
	RuntimeConfigGeneration  int64                     `json:"runtimeConfigGeneration,omitempty"`
	ResourceConfigGeneration int64                     `json:"resourceConfigGeneration,omitempty"`
	RealizedRuleRevision     string                    `json:"realizedRuleRevision,omitempty"`
	RealizedSkillRevision    string                    `json:"realizedSkillRevision,omitempty"`
	RealizedMCPRevision      string                    `json:"realizedMcpRevision,omitempty"`
	ObservedHomeStateID      string                    `json:"observedHomeStateId,omitempty"`
	StateGeneration          int64                     `json:"stateGeneration,omitempty"`
	Message                  string                    `json:"message,omitempty"`
	ActiveRunID              string                    `json:"activeRunId,omitempty"`
	UpdatedAt                *metav1.Time              `json:"updatedAt,omitempty"`
}

// AgentSessionResourceList lists agentSession resources.
type AgentSessionResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentSessionResource `json:"items"`
}

// AgentRunResource stores one internal agentRun state object.
type AgentRunResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AgentRunResourceSpec   `json:"spec,omitempty"`
	Status            AgentRunResourceStatus `json:"status,omitempty"`
}

// AgentRunResourceSpec stores one desired agentRun payload.
type AgentRunResourceSpec struct {
	Run *agentrunv1.AgentRunSpec `json:"run,omitempty"`
}

// AgentRunResourceStatus stores controller-owned agentRun observation.
type AgentRunResourceStatus struct {
	CommonStatusFields `json:",inline"`
	Phase              AgentRunResourcePhase                  `json:"phase,omitempty"`
	Message            string                                 `json:"message,omitempty"`
	WorkloadID         string                                 `json:"workloadId,omitempty"`
	ResultSummary      *AgentRunResultSummary                 `json:"resultSummary,omitempty"`
	PrepareJobs        []*agentrunv1.AgentRunPrepareJobStatus `json:"prepareJobs,omitempty"`
	UpdatedAt          *metav1.Time                           `json:"updatedAt,omitempty"`
}

// AgentRunResultSummary stores only the terminal outcome needed by control-plane
// retry and user-state projection. Full output remains outside Kubernetes status.
type AgentRunResultSummary struct {
	Status       string `json:"status,omitempty"`
	ErrorCode    string `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
	Retryable    bool   `json:"retryable,omitempty"`
}

// AgentRunResourceList lists agentRun resources.
type AgentRunResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentRunResource `json:"items"`
}

// AgentSessionActionResource stores one durable action in the serialization
// domain of one agentSession.
type AgentSessionActionResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AgentSessionActionResourceSpec   `json:"spec,omitempty"`
	Status            AgentSessionActionResourceStatus `json:"status,omitempty"`
}

// AgentSessionActionResourceSpec stores one durable action payload.
type AgentSessionActionResourceSpec struct {
	Action *agentsessionactionv1.AgentSessionActionSpec `json:"action,omitempty"`
}

// AgentSessionActionResourceStatus stores controller-owned action observation.
type AgentSessionActionResourceStatus struct {
	CommonStatusFields `json:",inline"`
	Phase              AgentSessionActionResourcePhase        `json:"phase,omitempty"`
	FailureClass       AgentSessionActionResourceFailureClass `json:"failureClass,omitempty"`
	Message            string                                 `json:"message,omitempty"`
	RetryCount         int32                                  `json:"retryCount,omitempty"`
	AttemptCount       int32                                  `json:"attemptCount,omitempty"`
	CandidateIndex     int32                                  `json:"candidateIndex,omitempty"`
	NextRetryAt        *metav1.Time                           `json:"nextRetryAt,omitempty"`
	RunID              string                                 `json:"runId,omitempty"`
	CreatedAt          *metav1.Time                           `json:"createdAt,omitempty"`
	UpdatedAt          *metav1.Time                           `json:"updatedAt,omitempty"`
}

// AgentSessionActionResourceList lists durable action resources.
type AgentSessionActionResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentSessionActionResource `json:"items"`
}
