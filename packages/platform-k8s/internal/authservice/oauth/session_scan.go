package oauth

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ScanSessions reconciles every persisted OAuth authorization session once.
func (r *SessionReconciler) ScanSessions(ctx context.Context) error {
	if r == nil {
		return nil
	}
	items, err := r.resourceStore.List(ctx)
	if err != nil {
		return err
	}
	for i := range items {
		key := ctrlclient.ObjectKeyFromObject(&items[i])
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			return err
		}
	}
	return r.sessionStore.DeleteExpiredSessions(ctx, r.now().UTC())
}
