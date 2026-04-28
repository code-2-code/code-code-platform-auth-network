package resourceops

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func CreateResource[T ctrlclient.Object](ctx context.Context, client ctrlclient.Client, obj T, namespace, name string) error {
	if err := client.Create(ctx, obj); err != nil {
		return fmt.Errorf("platformk8s: create %T %q in namespace %q: %w", obj, name, namespace, err)
	}
	return nil
}

func UpsertResource[T ctrlclient.Object](ctx context.Context, client ctrlclient.Client, next T, namespace, name string) error {
	key := types.NamespacedName{Namespace: namespace, Name: name}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := next.DeepCopyObject().(T)
		if err := client.Get(ctx, key, current); err != nil {
			if apierrors.IsNotFound(err) {
				return CreateResource(ctx, client, next, namespace, name)
			}
			return fmt.Errorf("platformk8s: get %T %q: %w", next, name, err)
		}
		preserveUnownedObjectMeta(current, next)
		next.SetResourceVersion(current.GetResourceVersion())
		return client.Update(ctx, next)
	}); err != nil {
		return fmt.Errorf("platformk8s: upsert %T %q: %w", next, name, err)
	}
	return nil
}

func preserveUnownedObjectMeta[T ctrlclient.Object](current T, next T) {
	next.SetLabels(mergeStringMap(current.GetLabels(), next.GetLabels()))
	next.SetAnnotations(mergeStringMap(current.GetAnnotations(), next.GetAnnotations()))
}

func mergeStringMap(base map[string]string, override map[string]string) map[string]string {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(override))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range override {
		out[key] = value
	}
	return out
}
