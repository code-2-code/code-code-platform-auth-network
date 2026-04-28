package temporalruntime

import (
	"context"
	"fmt"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

type Runtime struct {
	Client client.Client
	Worker worker.Worker
}

type RegisterFunc func(worker.Worker) error
type ScheduleFunc func(context.Context, client.Client, string) error

func Start(ctx context.Context, config Config, register RegisterFunc, ensureSchedules ScheduleFunc) (*Runtime, error) {
	client, err := Dial(ctx, config)
	if err != nil {
		return nil, err
	}
	worker := NewWorker(client, config.TaskQueue)
	if register != nil {
		if err := register(worker); err != nil {
			client.Close()
			return nil, err
		}
	}
	if ensureSchedules != nil {
		if err := ensureSchedules(ctx, client, config.TaskQueue); err != nil {
			client.Close()
			return nil, err
		}
	}
	if err := worker.Start(); err != nil {
		client.Close()
		return nil, fmt.Errorf("platformk8s/temporalruntime: start worker: %w", err)
	}
	return &Runtime{Client: client, Worker: worker}, nil
}

func (r *Runtime) Stop() {
	if r == nil {
		return
	}
	if r.Worker != nil {
		r.Worker.Stop()
	}
	if r.Client != nil {
		r.Client.Close()
	}
}
