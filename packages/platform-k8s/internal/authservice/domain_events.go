package authservice

import (
	"context"
	"fmt"
	"strings"
	"time"

	domaineventv1 "code-code.internal/go-contract/platform/domain_event/v1"
	"code-code.internal/platform-k8s/internal/authservice/credentials"
	"code-code.internal/platform-k8s/internal/platform/domainevents"
	"github.com/jackc/pgx/v5/pgxpool"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (s *Server) StartDomainEventConsumers(ctx context.Context, pool *pgxpool.Pool, natsURL string) error {
	if s == nil || s.oauthSessions == nil || s.oauthSessions.runtime == nil {
		return fmt.Errorf("platformk8s/authservice: oauth runtime is nil")
	}
	if strings.TrimSpace(natsURL) == "" {
		return nil
	}
	materialReconciler, err := credentials.NewMaterialReconciler(credentials.MaterialReconcilerConfig{
		Client:    s.client,
		Namespace: s.namespace,
		Store:     s.credentialStore,
		Material:  s.credentialMaterial,
	})
	if err != nil {
		return err
	}
	consumer, err := domainevents.NewConsumer(pool, domainevents.ConsumerConfig{
		NATSURL:     natsURL,
		ClientName:  "platform-auth-service-domain-consumer",
		DurableName: "platform-auth-service",
		FilterSubjects: []string{
			domainevents.SubjectPrefix + ".oauth_session.>",
			domainevents.SubjectPrefix + ".credential.>",
		},
	}, func(eventCtx context.Context, event *domaineventv1.DomainEvent) error {
		return s.handleDomainEvent(eventCtx, event, materialReconciler)
	})
	if err != nil {
		return err
	}
	go func() { _ = consumer.Run(ctx) }()
	return nil
}

func (s *Server) handleDomainEvent(ctx context.Context, event *domaineventv1.DomainEvent, material *credentials.MaterialReconciler) error {
	switch payload := event.GetPayload().(type) {
	case *domaineventv1.DomainEvent_OauthSession:
		sessionID := firstNonEmpty(payload.OauthSession.GetState().GetSpec().GetSessionId(), event.GetAggregateId())
		return s.reconcileOAuthSession(ctx, sessionID)
	case *domaineventv1.DomainEvent_Credential:
		credentialID := firstNonEmpty(payload.Credential.GetDefinition().GetCredentialId(), event.GetAggregateId())
		result, err := material.Reconcile(ctx, ctrl.Request{NamespacedName: ctrlclient.ObjectKey{Namespace: s.namespace, Name: credentialID}})
		s.scheduleReconcile(ctx, result, func(next context.Context) (ctrl.Result, error) {
			return material.Reconcile(next, ctrl.Request{NamespacedName: ctrlclient.ObjectKey{Namespace: s.namespace, Name: credentialID}})
		})
		return err
	default:
		return nil
	}
}

func (s *Server) reconcileOAuthSession(ctx context.Context, sessionID string) error {
	result, err := s.oauthSessions.runtime.sessionReconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: ctrlclient.ObjectKey{Namespace: s.namespace, Name: strings.TrimSpace(sessionID)},
	})
	s.scheduleReconcile(ctx, result, func(next context.Context) (ctrl.Result, error) {
		return s.oauthSessions.runtime.sessionReconciler.Reconcile(next, ctrl.Request{
			NamespacedName: ctrlclient.ObjectKey{Namespace: s.namespace, Name: strings.TrimSpace(sessionID)},
		})
	})
	return err
}

func (s *Server) scheduleReconcile(ctx context.Context, result ctrl.Result, run func(context.Context) (ctrl.Result, error)) {
	if !result.Requeue && result.RequeueAfter <= 0 {
		return
	}
	delay := result.RequeueAfter
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}
	time.AfterFunc(delay, func() {
		if ctx.Err() != nil {
			return
		}
		next, err := run(ctx)
		if err == nil {
			s.scheduleReconcile(ctx, next, run)
		}
	})
}
