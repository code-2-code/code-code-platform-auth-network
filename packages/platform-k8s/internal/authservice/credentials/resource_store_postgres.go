package credentials

import (
	"context"
	"errors"
	"fmt"
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	"code-code.internal/go-contract/domainerror"
	domaineventv1 "code-code.internal/go-contract/platform/domain_event/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"code-code.internal/platform-k8s/internal/platform/domainevents"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

type postgresResourceStore struct {
	pool      *pgxpool.Pool
	outbox    *domainevents.Outbox
	namespace string
}

func NewPostgresResourceStore(pool *pgxpool.Pool, outbox *domainevents.Outbox, namespace string) (ResourceStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("credentials: postgres resource store pool is nil")
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return nil, fmt.Errorf("credentials: postgres resource store namespace is empty")
	}
	return &postgresResourceStore{pool: pool, outbox: outbox, namespace: namespace}, nil
}

func (s *postgresResourceStore) List(ctx context.Context) ([]platformv1alpha1.CredentialDefinitionResource, error) {
	rows, err := s.pool.Query(ctx, `
select payload, generation
from platform_credentials
where payload->'metadata'->>'namespace' = $1
order by id`, s.namespace)
	if err != nil {
		return nil, fmt.Errorf("credentials: list credential records: %w", err)
	}
	defer rows.Close()
	items := []platformv1alpha1.CredentialDefinitionResource{}
	for rows.Next() {
		resource, err := scanCredentialResource(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *resource)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *postgresResourceStore) Get(ctx context.Context, credentialID string) (*platformv1alpha1.CredentialDefinitionResource, error) {
	var payload []byte
	var generation int64
	credentialID = strings.TrimSpace(credentialID)
	err := s.pool.QueryRow(ctx, `
select payload, generation
from platform_credentials
where id = $1 and payload->'metadata'->>'namespace' = $2`, credentialID, s.namespace).Scan(&payload, &generation)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("credentials: get credential record %q: %w", credentialID, err)
		}
		return nil, credentialNotFound(credentialID)
	}
	return decodeCredentialResource(payload, generation)
}

func (s *postgresResourceStore) Create(ctx context.Context, resource *platformv1alpha1.CredentialDefinitionResource) error {
	if err := normalizeCredentialResource(resource, s.namespace, 1); err != nil {
		return err
	}
	payload, err := encodeCredentialResource(resource)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var generation int64
	err = tx.QueryRow(ctx, `
insert into platform_credentials (id, payload, generation, created_at, updated_at)
values ($1, $2::jsonb, 1, now(), now())
on conflict (id) do nothing
returning generation`, resource.Name, payload).Scan(&generation)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return domainerror.NewAlreadyExists("platformk8s: credential %q already exists", resource.Name)
	}
	if err := s.enqueue(ctx, tx, resource, "created"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *postgresResourceStore) Upsert(ctx context.Context, resource *platformv1alpha1.CredentialDefinitionResource) error {
	if resource == nil {
		return domainerror.NewValidation("credentials: credential resource is nil")
	}
	current, err := s.Get(ctx, resource.Name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return s.Create(ctx, resource)
		}
		return err
	}
	next := resource.DeepCopy()
	if err := normalizeCredentialResource(next, s.namespace, current.Generation+1); err != nil {
		return err
	}
	return s.write(ctx, next, "updated")
}

func (s *postgresResourceStore) Update(ctx context.Context, credentialID string, mutate func(*platformv1alpha1.CredentialDefinitionResource) error) error {
	current, err := s.Get(ctx, credentialID)
	if err != nil {
		return err
	}
	if mutate != nil {
		if err := mutate(current); err != nil {
			return err
		}
	}
	if err := normalizeCredentialResource(current, s.namespace, current.Generation+1); err != nil {
		return err
	}
	return s.write(ctx, current, "updated")
}

func (s *postgresResourceStore) UpdateStatus(ctx context.Context, credentialID string, mutate func(*platformv1alpha1.CredentialDefinitionResource) error) error {
	current, err := s.Get(ctx, credentialID)
	if err != nil {
		return err
	}
	if mutate != nil {
		if err := mutate(current); err != nil {
			return err
		}
	}
	if err := normalizeCredentialResource(current, s.namespace, current.Generation); err != nil {
		return err
	}
	return s.write(ctx, current, "status_updated")
}

func (s *postgresResourceStore) Delete(ctx context.Context, credentialID string) error {
	current, err := s.Get(ctx, credentialID)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "delete from platform_credentials where id = $1", current.Name); err != nil {
		return err
	}
	if err := s.enqueue(ctx, tx, current, "deleted"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *postgresResourceStore) write(ctx context.Context, resource *platformv1alpha1.CredentialDefinitionResource, mutation string) error {
	payload, err := encodeCredentialResource(resource)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
update platform_credentials
set payload = $2::jsonb,
    generation = $3,
    updated_at = now()
where id = $1`, resource.Name, payload, resource.Generation); err != nil {
		return err
	}
	if err := s.enqueue(ctx, tx, resource, mutation); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *postgresResourceStore) enqueue(ctx context.Context, tx pgx.Tx, resource *platformv1alpha1.CredentialDefinitionResource, mutation string) error {
	if s.outbox == nil {
		return nil
	}
	var definition *credentialv1.CredentialDefinition
	if resource != nil && resource.Spec.Definition != nil {
		definition = proto.Clone(resource.Spec.Definition).(*credentialv1.CredentialDefinition)
	}
	return s.outbox.EnqueueTx(ctx, tx, &domaineventv1.DomainEvent{
		EventType:        mutation,
		AggregateType:    "credential",
		AggregateId:      resource.GetName(),
		AggregateVersion: resource.GetGeneration(),
		Payload: &domaineventv1.DomainEvent_Credential{Credential: &domaineventv1.CredentialEvent{
			Mutation:   credentialMutation(mutation),
			Definition: definition,
		}},
	})
}
