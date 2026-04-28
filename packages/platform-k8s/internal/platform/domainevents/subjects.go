package domainevents

import (
	"fmt"
	"strings"

	domaineventv1 "code-code.internal/go-contract/platform/domain_event/v1"
)

const (
	StreamName    = "PLATFORM_DOMAIN_EVENTS"
	SubjectPrefix = "platform.domain"

	AggregateAgentSession       = "agent_session"
	AggregateAgentSessionAction = "agent_session_action"
	AggregateAgentRun           = "agent_run"
	AggregateOAuthSession       = "oauth_session"
	AggregateCredential         = "credential"
	AggregateCatalog            = "catalog"
	AggregateCLIRuntime         = "cli_runtime"
)

func SubjectFor(event *domaineventv1.DomainEvent) string {
	if event == nil {
		return SubjectPrefix + ".unknown"
	}
	aggregate := subjectToken(event.GetAggregateType())
	mutation := subjectToken(strings.ToLower(event.GetEventType()))
	if mutation == "" || mutation == "_" {
		mutation = "changed"
	}
	return fmt.Sprintf("%s.%s.%s", SubjectPrefix, aggregate, mutation)
}

func subjectToken(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, ".", "_")
	value = strings.ReplaceAll(value, "*", "_")
	value = strings.ReplaceAll(value, ">", "_")
	if value == "" {
		return "_"
	}
	return value
}
