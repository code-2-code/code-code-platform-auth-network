package temporalruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
)

const (
	DefaultAddress   = "temporal-frontend.code-code-infra.svc.cluster.local:7233"
	DefaultNamespace = "default"
)

type Config struct {
	Address   string
	Namespace string
	TaskQueue string
}

func ConfigFromEnv(defaultTaskQueue string) Config {
	return Config{
		Address:   envOrDefault("TEMPORAL_ADDRESS", DefaultAddress),
		Namespace: envOrDefault("TEMPORAL_NAMESPACE", DefaultNamespace),
		TaskQueue: envOrDefault("TEMPORAL_TASK_QUEUE", defaultTaskQueue),
	}
}

func Dial(ctx context.Context, config Config) (client.Client, error) {
	if strings.TrimSpace(config.Address) == "" {
		return nil, fmt.Errorf("platformk8s/temporalruntime: address is empty")
	}
	namespace := strings.TrimSpace(config.Namespace)
	if namespace == "" {
		namespace = DefaultNamespace
	}
	return client.DialContext(ctx, client.Options{
		HostPort:  strings.TrimSpace(config.Address),
		Namespace: namespace,
	})
}

func NewWorker(client client.Client, taskQueue string) worker.Worker {
	return worker.New(client, strings.TrimSpace(taskQueue), worker.Options{})
}

type IntervalSchedule struct {
	ID         string
	WorkflowID string
	Workflow   any
	TaskQueue  string
	Every      time.Duration
	Offset     time.Duration
	Args       []any
}

func EnsureIntervalSchedule(ctx context.Context, temporalClient client.Client, spec IntervalSchedule) error {
	options, err := scheduleOptions(spec)
	if err != nil {
		return err
	}
	handle, err := temporalClient.ScheduleClient().Create(ctx, options)
	if err == nil {
		_ = handle
		return nil
	}
	if !errors.Is(err, temporal.ErrScheduleAlreadyRunning) {
		return err
	}
	return temporalClient.ScheduleClient().GetHandle(ctx, spec.ID).Update(ctx, client.ScheduleUpdateOptions{
		DoUpdate: func(client.ScheduleUpdateInput) (*client.ScheduleUpdate, error) {
			return &client.ScheduleUpdate{
				Schedule: &client.Schedule{
					Spec:   &options.Spec,
					Action: options.Action,
					Policy: &client.SchedulePolicies{
						Overlap:        options.Overlap,
						CatchupWindow:  options.CatchupWindow,
						PauseOnFailure: options.PauseOnFailure,
					},
					State: &client.ScheduleState{Note: options.Note},
				},
			}, nil
		},
	})
}

func scheduleOptions(spec IntervalSchedule) (client.ScheduleOptions, error) {
	id := strings.TrimSpace(spec.ID)
	if id == "" {
		return client.ScheduleOptions{}, fmt.Errorf("platformk8s/temporalruntime: schedule id is empty")
	}
	workflowID := strings.TrimSpace(spec.WorkflowID)
	if workflowID == "" {
		workflowID = id
	}
	if spec.Workflow == nil {
		return client.ScheduleOptions{}, fmt.Errorf("platformk8s/temporalruntime: workflow is nil")
	}
	taskQueue := strings.TrimSpace(spec.TaskQueue)
	if taskQueue == "" {
		return client.ScheduleOptions{}, fmt.Errorf("platformk8s/temporalruntime: task queue is empty")
	}
	if spec.Every <= 0 {
		return client.ScheduleOptions{}, fmt.Errorf("platformk8s/temporalruntime: schedule interval is empty")
	}
	return client.ScheduleOptions{
		ID: id,
		Spec: client.ScheduleSpec{
			Intervals:    []client.ScheduleIntervalSpec{{Every: spec.Every, Offset: spec.Offset}},
			TimeZoneName: "UTC",
		},
		Action: &client.ScheduleWorkflowAction{
			ID:        workflowID,
			Workflow:  spec.Workflow,
			Args:      spec.Args,
			TaskQueue: taskQueue,
		},
		Overlap:       enumspb.SCHEDULE_OVERLAP_POLICY_SKIP,
		CatchupWindow: time.Minute,
		Note:          "managed by platform service Temporal worker",
	}, nil
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
