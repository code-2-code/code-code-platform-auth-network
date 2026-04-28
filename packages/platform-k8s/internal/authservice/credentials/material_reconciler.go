package credentials

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const credentialMaterialRequeueInterval = 5 * time.Minute

// MaterialReconciler projects credential-local material readiness into status.
type MaterialReconciler struct {
	client        ctrlclient.Client
	namespace     string
	store         ResourceStore
	materialStore CredentialMaterialStore
	logger        *slog.Logger
	now           func() time.Time
}

// MaterialReconcilerConfig groups material readiness reconciler dependencies.
type MaterialReconcilerConfig struct {
	Client    ctrlclient.Client
	Namespace string
	Store     ResourceStore
	Material  CredentialMaterialStore
	Logger    *slog.Logger
	Now       func() time.Time
}

// NewMaterialReconciler creates one credential material readiness reconciler.
func NewMaterialReconciler(config MaterialReconcilerConfig) (*MaterialReconciler, error) {
	switch {
	case config.Client == nil:
		return nil, fmt.Errorf("credentials: material reconciler client is nil")
	case strings.TrimSpace(config.Namespace) == "":
		return nil, fmt.Errorf("credentials: material reconciler namespace is empty")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	store := config.Store
	if store == nil {
		var err error
		store, err = NewKubernetesResourceStore(config.Client, config.Namespace)
		if err != nil {
			return nil, err
		}
	}
	materialStore := config.Material
	if materialStore == nil {
		return nil, fmt.Errorf("credentials: material reconciler material store is nil")
	}
	return &MaterialReconciler{
		client:        config.Client,
		namespace:     strings.TrimSpace(config.Namespace),
		store:         store,
		materialStore: materialStore,
		logger:        config.Logger,
		now:           config.Now,
	}, nil
}

// Reconcile validates one credential's auth material and writes MaterialReady.
func (r *MaterialReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	if request.Namespace != r.namespace {
		return ctrl.Result{}, nil
	}
	resource, err := r.store.Get(ctx, request.Name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if resource.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}
	if err := r.updateMaterialStatus(ctx, request.NamespacedName); err != nil {
		r.logger.Error("credential material status update failed", "name", request.NamespacedName.String(), "error", err)
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: credentialMaterialRequeueInterval}, nil
}

func (r *MaterialReconciler) updateMaterialStatus(ctx context.Context, key types.NamespacedName) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := r.store.Get(ctx, key.Name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		next := current.Status.DeepCopy()
		next.ObservedGeneration = current.GetGeneration()
		condition := materialConditionForResource(ctx, r.materialStore, current, r.now())
		meta.SetStatusCondition(&next.Conditions, condition)
		if equality.Semantic.DeepEqual(current.Status, *next) {
			return nil
		}
		current.Status = *next
		return r.store.UpdateStatus(ctx, key.Name, func(target *platformv1alpha1.CredentialDefinitionResource) error {
			target.Status = *next
			return nil
		})
	})
}

func materialConditionForResource(
	ctx context.Context,
	materialStore CredentialMaterialStore,
	resource *platformv1alpha1.CredentialDefinitionResource,
	now time.Time,
) metav1.Condition {
	status := metav1.ConditionTrue
	reason := "MaterialResolved"
	message := "Credential auth material is ready."
	if err := validateCredentialResourceMaterial(ctx, materialStore, resource); err != nil {
		status = metav1.ConditionFalse
		reason = "MaterialInvalid"
		message = err.Error()
	}
	condition := metav1.Condition{
		Type:               ConditionCredentialMaterialReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: resource.GetGeneration(),
		LastTransitionTime: metav1.NewTime(now.UTC()),
	}
	previous := meta.FindStatusCondition(resource.Status.Conditions, ConditionCredentialMaterialReady)
	if previous != nil &&
		previous.Status == condition.Status &&
		previous.Reason == condition.Reason &&
		previous.Message == condition.Message &&
		previous.ObservedGeneration == condition.ObservedGeneration {
		condition.LastTransitionTime = previous.LastTransitionTime
	}
	return condition
}
