// Package credential defines the platform behavior contract for resolving
// credentials used by provider runtimes.
package credential

import (
	"context"

	credentialv1 "code-code.internal/go-contract/credential/v1"
)

// CredentialRef references one credential by stable identity.
type CredentialRef = credentialv1.CredentialRef

// CredentialDefinition describes one credential resource owned by the platform.
type CredentialDefinition = credentialv1.CredentialDefinition

// ResolvedCredential describes one provider-ready resolved credential.
type ResolvedCredential = credentialv1.ResolvedCredential

// Resolver resolves platform credentials for provider-managed runtimes.
type Resolver interface {
	// Get returns the configured credential definition referenced by ref.
	Get(ctx context.Context, ref *CredentialRef) (*CredentialDefinition, error)

	// Resolve returns the provider-ready credential material referenced by ref.
	Resolve(ctx context.Context, ref *CredentialRef) (*ResolvedCredential, error)
}
