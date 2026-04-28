package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	domaineventv1 "code-code.internal/go-contract/platform/domain_event/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"code-code.internal/platform-k8s/internal/platform/domainevents"
	"code-code.internal/platform-k8s/internal/platform/resourceops"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type AuthorizationSessionResourceStore interface {
	List(ctx context.Context) ([]platformv1alpha1.OAuthAuthorizationSessionResource, error)
	Get(ctx context.Context, sessionID string) (*platformv1alpha1.OAuthAuthorizationSessionResource, error)
	Create(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource) error
	Update(ctx context.Context, sessionID string, mutate func(*platformv1alpha1.OAuthAuthorizationSessionResource) error) error
	UpdateStatus(ctx context.Context, sessionID string, mutate func(*platformv1alpha1.OAuthAuthorizationSessionResource) error) error
	Delete(ctx context.Context, sessionID string) error
}

type kubernetesAuthorizationSessionResourceStore struct {
	client    ctrlclient.Client
	reader    ctrlclient.Reader
	namespace string
}

func NewKubernetesAuthorizationSessionResourceStore(client ctrlclient.Client, reader ctrlclient.Reader, namespace string) (AuthorizationSessionResourceStore, error) {
	if client == nil {
		return nil, fmt.Errorf("platformk8s/oauth: authorization session store client is nil")
	}
	if reader == nil {
		reader = client
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return nil, fmt.Errorf("platformk8s/oauth: authorization session store namespace is empty")
	}
	return kubernetesAuthorizationSessionResourceStore{client: client, reader: reader, namespace: namespace}, nil
}

func (s kubernetesAuthorizationSessionResourceStore) List(ctx context.Context) ([]platformv1alpha1.OAuthAuthorizationSessionResource, error) {
	list := &platformv1alpha1.OAuthAuthorizationSessionResourceList{}
	if err := s.reader.List(ctx, list, ctrlclient.InNamespace(s.namespace)); err != nil {
		return nil, err
	}
	return append([]platformv1alpha1.OAuthAuthorizationSessionResource(nil), list.Items...), nil
}

func (s kubernetesAuthorizationSessionResourceStore) Get(ctx context.Context, sessionID string) (*platformv1alpha1.OAuthAuthorizationSessionResource, error) {
	resource := &platformv1alpha1.OAuthAuthorizationSessionResource{}
	if err := s.reader.Get(ctx, authSessionObjectKey(s.namespace, sessionID), resource); err != nil {
		return nil, err
	}
	return resource, nil
}

func (s kubernetesAuthorizationSessionResourceStore) Create(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource) error {
	return resourceops.CreateResource(ctx, s.client, resource, s.namespace, resource.Name)
}

func (s kubernetesAuthorizationSessionResourceStore) Update(ctx context.Context, sessionID string, mutate func(*platformv1alpha1.OAuthAuthorizationSessionResource) error) error {
	return resourceops.UpdateResource(ctx, s.client, authSessionObjectKey(s.namespace, sessionID), mutate, func() *platformv1alpha1.OAuthAuthorizationSessionResource {
		return &platformv1alpha1.OAuthAuthorizationSessionResource{}
	})
}

func (s kubernetesAuthorizationSessionResourceStore) UpdateStatus(ctx context.Context, sessionID string, mutate func(*platformv1alpha1.OAuthAuthorizationSessionResource) error) error {
	return resourceops.UpdateStatus(ctx, s.client, authSessionObjectKey(s.namespace, sessionID), mutate, func() *platformv1alpha1.OAuthAuthorizationSessionResource {
		return &platformv1alpha1.OAuthAuthorizationSessionResource{}
	})
}

func (s kubernetesAuthorizationSessionResourceStore) Delete(ctx context.Context, sessionID string) error {
	return resourceops.DeleteResource(ctx, s.client, &platformv1alpha1.OAuthAuthorizationSessionResource{}, s.namespace, strings.TrimSpace(sessionID))
}

type postgresAuthorizationSessionResourceStore struct {
	pool      *pgxpool.Pool
	outbox    *domainevents.Outbox
	namespace string
}

func NewPostgresAuthorizationSessionResourceStore(pool *pgxpool.Pool, outbox *domainevents.Outbox, namespace string) (AuthorizationSessionResourceStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("platformk8s/oauth: authorization session postgres pool is nil")
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return nil, fmt.Errorf("platformk8s/oauth: authorization session namespace is empty")
	}
	return &postgresAuthorizationSessionResourceStore{pool: pool, outbox: outbox, namespace: namespace}, nil
}

func (s *postgresAuthorizationSessionResourceStore) List(ctx context.Context) ([]platformv1alpha1.OAuthAuthorizationSessionResource, error) {
	rows, err := s.pool.Query(ctx, `
select payload, generation
from platform_oauth_sessions
where payload->'metadata'->>'namespace' = $1
order by id`, s.namespace)
	if err != nil {
		return nil, fmt.Errorf("platformk8s/oauth: list authorization sessions: %w", err)
	}
	defer rows.Close()
	items := []platformv1alpha1.OAuthAuthorizationSessionResource{}
	for rows.Next() {
		resource, err := scanAuthorizationSessionResource(rows)
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

func (s *postgresAuthorizationSessionResourceStore) Get(ctx context.Context, sessionID string) (*platformv1alpha1.OAuthAuthorizationSessionResource, error) {
	sessionID = strings.TrimSpace(sessionID)
	var payload []byte
	var generation int64
	err := s.pool.QueryRow(ctx, `
select payload, generation
from platform_oauth_sessions
where id = $1 and payload->'metadata'->>'namespace' = $2`, sessionID, s.namespace).Scan(&payload, &generation)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("platformk8s/oauth: get authorization session %q: %w", sessionID, err)
		}
		return nil, authorizationSessionNotFound(sessionID)
	}
	return decodeAuthorizationSessionResource(payload, generation)
}

func (s *postgresAuthorizationSessionResourceStore) Create(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource) error {
	if err := normalizeAuthorizationSessionResource(resource, s.namespace, 1); err != nil {
		return err
	}
	payload, err := encodeAuthorizationSessionResource(resource)
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
insert into platform_oauth_sessions (id, payload, generation, created_at, updated_at)
values ($1, $2::jsonb, 1, now(), now())
on conflict (id) do nothing
returning generation`, resource.Name, payload).Scan(&generation)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return apierrors.NewAlreadyExists(schema.GroupResource{Group: "platform.code-code.internal", Resource: "oauthauthorizationsessions"}, resource.Name)
	}
	if err := s.enqueue(ctx, tx, resource, "created"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *postgresAuthorizationSessionResourceStore) Update(ctx context.Context, sessionID string, mutate func(*platformv1alpha1.OAuthAuthorizationSessionResource) error) error {
	current, err := s.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	if mutate != nil {
		if err := mutate(current); err != nil {
			return err
		}
	}
	if err := normalizeAuthorizationSessionResource(current, s.namespace, current.Generation+1); err != nil {
		return err
	}
	return s.write(ctx, current, "updated")
}

func (s *postgresAuthorizationSessionResourceStore) UpdateStatus(ctx context.Context, sessionID string, mutate func(*platformv1alpha1.OAuthAuthorizationSessionResource) error) error {
	current, err := s.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	if mutate != nil {
		if err := mutate(current); err != nil {
			return err
		}
	}
	if err := normalizeAuthorizationSessionResource(current, s.namespace, current.Generation); err != nil {
		return err
	}
	return s.write(ctx, current, "status_updated")
}

func (s *postgresAuthorizationSessionResourceStore) Delete(ctx context.Context, sessionID string) error {
	current, err := s.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "delete from platform_oauth_sessions where id = $1", current.Name); err != nil {
		return err
	}
	if err := s.enqueue(ctx, tx, current, "deleted"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *postgresAuthorizationSessionResourceStore) write(ctx context.Context, resource *platformv1alpha1.OAuthAuthorizationSessionResource, mutation string) error {
	payload, err := encodeAuthorizationSessionResource(resource)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
update platform_oauth_sessions
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

func (s *postgresAuthorizationSessionResourceStore) enqueue(ctx context.Context, tx pgx.Tx, resource *platformv1alpha1.OAuthAuthorizationSessionResource, mutation string) error {
	if s.outbox == nil {
		return nil
	}
	return s.outbox.EnqueueTx(ctx, tx, &domaineventv1.DomainEvent{
		EventType:        mutation,
		AggregateType:    "oauth_session",
		AggregateId:      resource.GetName(),
		AggregateVersion: resource.GetGeneration(),
		Payload: &domaineventv1.DomainEvent_OauthSession{OauthSession: &domaineventv1.OAuthSessionEvent{
			Mutation: credentialMutation(mutation),
			State:    sessionStateFromResource(resource),
		}},
	})
}

type authorizationSessionRowScanner interface {
	Scan(...any) error
}

func scanAuthorizationSessionResource(row authorizationSessionRowScanner) (*platformv1alpha1.OAuthAuthorizationSessionResource, error) {
	var payload []byte
	var generation int64
	if err := row.Scan(&payload, &generation); err != nil {
		return nil, fmt.Errorf("platformk8s/oauth: scan authorization session: %w", err)
	}
	return decodeAuthorizationSessionResource(payload, generation)
}

func decodeAuthorizationSessionResource(payload []byte, generation int64) (*platformv1alpha1.OAuthAuthorizationSessionResource, error) {
	resource := &platformv1alpha1.OAuthAuthorizationSessionResource{}
	if err := json.Unmarshal(payload, resource); err != nil {
		return nil, fmt.Errorf("platformk8s/oauth: decode authorization session: %w", err)
	}
	resource.Generation = generation
	resource.ResourceVersion = strconv.FormatInt(generation, 10)
	return resource, nil
}

func encodeAuthorizationSessionResource(resource *platformv1alpha1.OAuthAuthorizationSessionResource) (string, error) {
	payload, err := json.Marshal(resource)
	if err != nil {
		return "", fmt.Errorf("platformk8s/oauth: encode authorization session %q: %w", resource.GetName(), err)
	}
	return string(payload), nil
}

func normalizeAuthorizationSessionResource(resource *platformv1alpha1.OAuthAuthorizationSessionResource, namespace string, generation int64) error {
	if resource == nil {
		return fmt.Errorf("platformk8s/oauth: authorization session resource is nil")
	}
	if strings.TrimSpace(resource.Name) == "" {
		return fmt.Errorf("platformk8s/oauth: authorization session resource name is empty")
	}
	resource.Namespace = strings.TrimSpace(namespace)
	if resource.CreationTimestamp.Time.IsZero() {
		resource.CreationTimestamp = metav1.NewTime(time.Now().UTC())
	}
	if generation <= 0 {
		generation = 1
	}
	resource.Generation = generation
	resource.ResourceVersion = strconv.FormatInt(generation, 10)
	return nil
}

func credentialMutation(value string) domaineventv1.DomainMutation {
	switch strings.TrimSpace(value) {
	case "created":
		return domaineventv1.DomainMutation_DOMAIN_MUTATION_CREATED
	case "status_updated":
		return domaineventv1.DomainMutation_DOMAIN_MUTATION_STATUS_UPDATED
	case "deleted":
		return domaineventv1.DomainMutation_DOMAIN_MUTATION_DELETED
	default:
		return domaineventv1.DomainMutation_DOMAIN_MUTATION_UPDATED
	}
}

func authorizationSessionNotFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "platform.code-code.internal", Resource: "oauthauthorizationsessions"}, strings.TrimSpace(name))
}

func authSessionObjectKey(namespace string, sessionID string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: strings.TrimSpace(sessionID)}
}
