package credentials

import (
	"context"
	"time"
)

// EnsureFreshOptions configures one runtime ensure-fresh execution.
type EnsureFreshOptions struct {
	MinTTL       time.Duration
	ForceRefresh bool
}

// EnsureFresh resolves one credential and refreshes tokens when required.
func (r *RefreshRunner) EnsureFresh(ctx context.Context, credentialID string, options EnsureFreshOptions) (*EnsureFreshResult, error) {
	return r.runCredential(ctx, credentialID, ensureFreshRunOneOptions(options))
}
