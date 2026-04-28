package domainevents

import (
	"context"
	"fmt"
	"strings"
	"time"

	domaineventv1 "code-code.internal/go-contract/platform/domain_event/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Outbox struct {
	pool     *pgxpool.Pool
	producer string
}

type Record struct {
	EventID string
	Subject string
	Payload []byte
}

func NewOutbox(pool *pgxpool.Pool, producer string) (*Outbox, error) {
	if pool == nil {
		return nil, fmt.Errorf("domainevents: postgres pool is nil")
	}
	producer = strings.TrimSpace(producer)
	if producer == "" {
		producer = "platform-k8s"
	}
	return &Outbox{pool: pool, producer: producer}, nil
}

func (o *Outbox) Enqueue(ctx context.Context, event *domaineventv1.DomainEvent) error {
	if o == nil || o.pool == nil {
		return fmt.Errorf("domainevents: outbox is nil")
	}
	return o.enqueue(ctx, o.pool, event)
}

func (o *Outbox) EnqueueTx(ctx context.Context, tx pgx.Tx, event *domaineventv1.DomainEvent) error {
	if tx == nil {
		return fmt.Errorf("domainevents: tx is nil")
	}
	return o.enqueue(ctx, tx, event)
}

func (o *Outbox) enqueue(ctx context.Context, exec interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, event *domaineventv1.DomainEvent) error {
	if event == nil {
		return fmt.Errorf("domainevents: event is nil")
	}
	normalizeEvent(event, o.producer)
	payload, err := proto.Marshal(event)
	if err != nil {
		return fmt.Errorf("domainevents: marshal event: %w", err)
	}
	if _, err := exec.Exec(ctx, `
insert into platform_domain_outbox (
	event_id, subject, payload, aggregate_type, aggregate_id, aggregate_version
) values ($1, $2, $3, $4, $5, $6)
on conflict (event_id) do nothing`,
		event.GetEventId(),
		SubjectFor(event),
		payload,
		event.GetAggregateType(),
		event.GetAggregateId(),
		event.GetAggregateVersion(),
	); err != nil {
		return fmt.Errorf("domainevents: enqueue %q: %w", event.GetEventId(), err)
	}
	return nil
}

func (o *Outbox) Claim(ctx context.Context, batchSize int) ([]Record, error) {
	if o == nil || o.pool == nil {
		return nil, fmt.Errorf("domainevents: outbox is nil")
	}
	if batchSize <= 0 {
		batchSize = 32
	}
	rows, err := o.pool.Query(ctx, `
with next as (
	select event_id
	from platform_domain_outbox
	where published_at is null
	order by created_at, event_id
	limit $1
	for update skip locked
)
update platform_domain_outbox outbox
set attempts = outbox.attempts + 1
from next
where outbox.event_id = next.event_id
returning outbox.event_id, outbox.subject, outbox.payload`, batchSize)
	if err != nil {
		return nil, fmt.Errorf("domainevents: claim outbox: %w", err)
	}
	defer rows.Close()
	records := []Record{}
	for rows.Next() {
		var record Record
		if err := rows.Scan(&record.EventID, &record.Subject, &record.Payload); err != nil {
			return nil, fmt.Errorf("domainevents: scan outbox: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("domainevents: iterate outbox: %w", err)
	}
	return records, nil
}

func (o *Outbox) MarkPublished(ctx context.Context, eventID string) error {
	return o.mark(ctx, eventID, "", true)
}

func (o *Outbox) MarkFailed(ctx context.Context, eventID string, publishErr error) error {
	message := ""
	if publishErr != nil {
		message = publishErr.Error()
	}
	return o.mark(ctx, eventID, message, false)
}

func (o *Outbox) mark(ctx context.Context, eventID string, message string, published bool) error {
	if o == nil || o.pool == nil {
		return fmt.Errorf("domainevents: outbox is nil")
	}
	eventID = strings.TrimSpace(eventID)
	if eventID == "" {
		return nil
	}
	query := "update platform_domain_outbox set last_error = $2 where event_id = $1"
	if published {
		query = "update platform_domain_outbox set published_at = now(), last_error = '' where event_id = $1"
		_, err := o.pool.Exec(ctx, query, eventID)
		return err
	}
	_, err := o.pool.Exec(ctx, query, eventID, strings.TrimSpace(message))
	return err
}

func normalizeEvent(event *domaineventv1.DomainEvent, producer string) {
	if strings.TrimSpace(event.EventId) == "" {
		event.EventId = nuid.Next()
	}
	if event.OccurredAt == nil {
		event.OccurredAt = timestamppb.New(time.Now().UTC())
	}
	if strings.TrimSpace(event.Producer) == "" {
		event.Producer = producer
	}
}
