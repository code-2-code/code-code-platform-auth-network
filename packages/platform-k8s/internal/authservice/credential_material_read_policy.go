package authservice

import (
	"context"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CredentialMaterialReadAuthorizer validates that a caller-requested material
// read is allowed by a support-owned policy.
type CredentialMaterialReadAuthorizer interface {
	AuthorizeCredentialMaterialRead(
		ctx context.Context,
		policyRef *authv1.CredentialMaterialReadPolicyRef,
		fieldIDs []string,
	) ([]string, error)
}

type denyCredentialMaterialReadAuthorizer struct{}

func (denyCredentialMaterialReadAuthorizer) AuthorizeCredentialMaterialRead(
	context.Context,
	*authv1.CredentialMaterialReadPolicyRef,
	[]string,
) ([]string, error) {
	return nil, status.Error(codes.Unavailable, "credential material read policy is not configured")
}
