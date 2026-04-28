package domainevents

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	domaineventv1 "code-code.internal/go-contract/platform/domain_event/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"
)

type Handler func(context.Context, *domaineventv1.DomainEvent) error

type ConsumerConfig struct {
	NATSURL        string
	ClientName     string
	DurableName    string
	FilterSubjects []string
	Logger         *slog.Logger
}

type Consumer struct {
	pool    *pgxpool.Pool
	config  ConsumerConfig
	handler Handler
}

func NewConsumer(pool *pgxpool.Pool, config ConsumerConfig, handler Handler) (*Consumer, error) {
	if pool == nil {
		return nil, fmt.Errorf("domainevents: consumer pool is nil")
	}
	if strings.TrimSpace(config.NATSURL) == "" {
		return nil, fmt.Errorf("domainevents: consumer nats url is empty")
	}
	if strings.TrimSpace(config.DurableName) == "" {
		return nil, fmt.Errorf("domainevents: consumer durable name is empty")
	}
	if len(config.FilterSubjects) == 0 {
		config.FilterSubjects = []string{SubjectPrefix + ".>"}
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if handler == nil {
		return nil, fmt.Errorf("domainevents: consumer handler is nil")
	}
	return &Consumer{pool: pool, config: config, handler: handler}, nil
}

func (c *Consumer) Run(ctx context.Context) error {
	nc, js, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer nc.Close()
	stream, err := js.Stream(ctx, StreamName)
	if err != nil {
		return fmt.Errorf("domainevents: get stream: %w", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Name:           c.config.DurableName,
		Durable:        c.config.DurableName,
		FilterSubjects: c.config.FilterSubjects,
		AckPolicy:      jetstream.AckExplicitPolicy,
		DeliverPolicy:  jetstream.DeliverAllPolicy,
		AckWait:        30 * time.Second,
		MaxDeliver:     8,
		BackOff: []time.Duration{
			time.Second,
			5 * time.Second,
			15 * time.Second,
			time.Minute,
		},
		MaxAckPending: 64,
	})
	if err != nil {
		return fmt.Errorf("domainevents: create consumer: %w", err)
	}
	messages, err := consumer.Messages(jetstream.PullMaxMessages(16))
	if err != nil {
		return fmt.Errorf("domainevents: open consumer messages: %w", err)
	}
	defer messages.Stop()
	for {
		msg, err := messages.Next(jetstream.NextContext(ctx))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("domainevents: next message: %w", err)
		}
		c.handle(ctx, msg)
	}
}

func (c *Consumer) handle(ctx context.Context, msg jetstream.Msg) {
	event := &domaineventv1.DomainEvent{}
	if err := proto.Unmarshal(msg.Data(), event); err != nil {
		_ = msg.Term()
		c.config.Logger.Error("domain event decode failed", "error", err)
		return
	}
	processed, err := c.processed(ctx, event.GetEventId())
	if err != nil {
		_ = msg.Nak()
		c.config.Logger.Error("domain event idempotency check failed", "event_id", event.GetEventId(), "error", err)
		return
	}
	if processed {
		_ = msg.Ack()
		return
	}
	if err := c.handler(ctx, event); err != nil {
		_ = msg.Nak()
		c.config.Logger.Error("domain event handler failed", "event_id", event.GetEventId(), "error", err)
		return
	}
	if err := c.markProcessed(ctx, event.GetEventId()); err != nil {
		_ = msg.Nak()
		c.config.Logger.Error("domain event idempotency mark failed", "event_id", event.GetEventId(), "error", err)
		return
	}
	_ = msg.Ack()
}

func (c *Consumer) connect(ctx context.Context) (*nats.Conn, jetstream.JetStream, error) {
	options := []nats.Option{}
	if name := strings.TrimSpace(c.config.ClientName); name != "" {
		options = append(options, nats.Name(name))
	}
	nc, err := nats.Connect(c.config.NATSURL, options...)
	if err != nil {
		return nil, nil, fmt.Errorf("domainevents: connect nats: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, nil, fmt.Errorf("domainevents: create jetstream client: %w", err)
	}
	if err := ensureStream(ctx, js); err != nil {
		nc.Close()
		return nil, nil, err
	}
	return nc, js, nil
}

func (c *Consumer) processed(ctx context.Context, eventID string) (bool, error) {
	var exists bool
	err := c.pool.QueryRow(ctx, `
select exists (
	select 1 from platform_domain_consumer_events
	where consumer_name = $1 and event_id = $2
)`, c.config.DurableName, eventID).Scan(&exists)
	return exists, err
}

func (c *Consumer) markProcessed(ctx context.Context, eventID string) error {
	_, err := c.pool.Exec(ctx, `
insert into platform_domain_consumer_events (consumer_name, event_id)
values ($1, $2)
on conflict do nothing`, c.config.DurableName, eventID)
	return err
}
