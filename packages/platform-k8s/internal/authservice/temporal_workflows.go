package authservice

import (
	"context"
	"fmt"
	"time"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	"code-code.internal/platform-k8s/internal/platform/temporalruntime"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

const (
	TemporalTaskQueue = "platform-auth-service"

	OAuthMaintenanceWorkflowName  = "platform.auth.oauthMaintenance"
	refreshOAuthDueActivityName   = "platform.auth.refreshOAuthDue"
	scanOAuthSessionsActivityName = "platform.auth.scanOAuthSessions"
)

func RegisterTemporalWorkflows(worker worker.Worker, server *Server) error {
	if worker == nil {
		return fmt.Errorf("platformk8s/authservice: temporal worker is nil")
	}
	if server == nil {
		return fmt.Errorf("platformk8s/authservice: server is nil")
	}
	worker.RegisterWorkflowWithOptions(OAuthMaintenanceWorkflow, workflow.RegisterOptions{Name: OAuthMaintenanceWorkflowName})
	activities := &TemporalActivities{server: server}
	worker.RegisterActivityWithOptions(activities.RefreshOAuthDue, activity.RegisterOptions{Name: refreshOAuthDueActivityName})
	worker.RegisterActivityWithOptions(activities.ScanOAuthSessions, activity.RegisterOptions{Name: scanOAuthSessionsActivityName})
	return nil
}

func EnsureTemporalSchedules(ctx context.Context, client client.Client, taskQueue string) error {
	return temporalruntime.EnsureIntervalSchedule(ctx, client, temporalruntime.IntervalSchedule{
		ID:         "oauth-maintenance",
		WorkflowID: "oauth-maintenance",
		Workflow:   OAuthMaintenanceWorkflowName,
		TaskQueue:  taskQueue,
		Every:      time.Minute,
	})
}

func OAuthMaintenanceWorkflow(ctx workflow.Context) error {
	options := workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval: time.Second,
			MaximumInterval: 30 * time.Second,
			MaximumAttempts: 3,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, options)
	if err := workflow.ExecuteActivity(ctx, refreshOAuthDueActivityName).Get(ctx, nil); err != nil {
		return err
	}
	return workflow.ExecuteActivity(ctx, scanOAuthSessionsActivityName).Get(ctx, nil)
}

type TemporalActivities struct {
	server *Server
}

func (a *TemporalActivities) RefreshOAuthDue(ctx context.Context) error {
	if a == nil || a.server == nil {
		return fmt.Errorf("platformk8s/authservice: temporal activity server is nil")
	}
	_, err := a.server.RefreshOAuthDue(ctx, &authv1.RefreshOAuthDueRequest{})
	return err
}

func (a *TemporalActivities) ScanOAuthSessions(ctx context.Context) error {
	if a == nil || a.server == nil {
		return fmt.Errorf("platformk8s/authservice: temporal activity server is nil")
	}
	_, err := a.server.ScanOAuthSessions(ctx, &authv1.ScanOAuthSessionsRequest{})
	return err
}
