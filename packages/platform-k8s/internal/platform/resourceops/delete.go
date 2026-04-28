package resourceops

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func DeleteResource[T ctrlclient.Object](ctx context.Context, client ctrlclient.Client, obj T, namespace, name string) error {
	key := types.NamespacedName{Namespace: namespace, Name: name}
	if err := client.Get(ctx, key, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil // idempotent
		}
		return fmt.Errorf("platformk8s: get %T %q for delete: %w", obj, name, err)
	}
	if err := client.Delete(ctx, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("platformk8s: delete %T %q: %w", obj, name, err)
	}
	return nil
}
