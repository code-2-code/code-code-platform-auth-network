package domainevents

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const protobufContentType = "application/x-protobuf"

type PublisherConfig struct {
	NATSURL    string
	ClientName string
	BatchSize  int
	Interval   time.Duration
	Logger     *slog.Logger
}

type Publisher struct {
	outbox   *Outbox
	config   PublisherConfig
	nc       *nats.Conn
	js       jetstream.JetStream
	ensured  bool
	closeErr error
}

func NewPublisher(outbox *Outbox, config PublisherConfig) (*Publisher, error) {
	if outbox == nil {
		return nil, fmt.Errorf("domainevents: publisher outbox is nil")
	}
	if strings.TrimSpace(config.NATSURL) == "" {
		return nil, fmt.Errorf("domainevents: publisher nats url is empty")
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 32
	}
	if config.Interval <= 0 {
		config.Interval = time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Publisher{outbox: outbox, config: config}, nil
}

func (p *Publisher) Run(ctx context.Context) error {
	if p == nil {
		return fmt.Errorf("domainevents: publisher is nil")
	}
	ticker := time.NewTicker(p.config.Interval)
	defer ticker.Stop()
	for {
		if err := p.PublishPending(ctx); err != nil && ctx.Err() == nil {
			p.config.Logger.Error("domain event publish batch failed", "error", err)
		}
		select {
		case <-ctx.Done():
			p.Close()
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *Publisher) PublishPending(ctx context.Context) error {
	records, err := p.outbox.Claim(ctx, p.config.BatchSize)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	js, err := p.jetStream(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		msg := &nats.Msg{
			Subject: record.Subject,
			Data:    record.Payload,
			Header: nats.Header{
				"content-type":  []string{protobufContentType},
				"proto-message": []string{"platform.domain_event.v1.DomainEvent"},
			},
		}
		if _, err := js.PublishMsg(ctx, msg, jetstream.WithMsgID(record.EventID)); err != nil {
			_ = p.outbox.MarkFailed(ctx, record.EventID, err)
			continue
		}
		if err := p.outbox.MarkPublished(ctx, record.EventID); err != nil {
			return err
		}
	}
	return nil
}

func (p *Publisher) Close() {
	if p == nil || p.nc == nil {
		return
	}
	p.nc.Close()
	p.nc = nil
	p.js = nil
	p.ensured = false
}

func (p *Publisher) jetStream(ctx context.Context) (jetstream.JetStream, error) {
	if p.js != nil {
		return p.js, nil
	}
	options := []nats.Option{}
	if name := strings.TrimSpace(p.config.ClientName); name != "" {
		options = append(options, nats.Name(name))
	}
	nc, err := nats.Connect(p.config.NATSURL, options...)
	if err != nil {
		return nil, fmt.Errorf("domainevents: connect nats: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("domainevents: create jetstream client: %w", err)
	}
	if err := ensureStream(ctx, js); err != nil {
		nc.Close()
		return nil, err
	}
	p.nc = nc
	p.js = js
	p.ensured = true
	return js, nil
}

func ensureStream(ctx context.Context, js jetstream.JetStream) error {
	_, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:        StreamName,
		Description: "Platform protobuf domain event stream.",
		Subjects:    []string{SubjectPrefix + ".>"},
		Retention:   jetstream.LimitsPolicy,
		MaxMsgs:     -1,
		MaxBytes:    -1,
		MaxAge:      7 * 24 * time.Hour,
		Storage:     jetstream.FileStorage,
		Replicas:    1,
		Duplicates:  2 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("domainevents: ensure stream: %w", err)
	}
	return nil
}
