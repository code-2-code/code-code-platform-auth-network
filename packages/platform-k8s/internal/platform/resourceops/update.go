package resourceops

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// UpdateResource retries a spec/metadata resource update against the latest object.
func UpdateResource[T ctrlclient.Object](ctx context.Context, client ctrlclient.Client, key types.NamespacedName, mutate func(T) error, newObject func() T) error {
	if client == nil {
		return fmt.Errorf("platformk8s: update client is nil")
	}
	if mutate == nil {
		return fmt.Errorf("platformk8s: update mutate function is nil")
	}
	if newObject == nil {
		return fmt.Errorf("platformk8s: update object factory is nil")
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := newObject()
		if err := client.Get(ctx, key, current); err != nil {
			return err
		}
		if err := mutate(current); err != nil {
			return err
		}
		return client.Update(ctx, current)
	}); err != nil {
		return fmt.Errorf("platformk8s: update %q: %w", key.String(), err)
	}
	return nil
}
