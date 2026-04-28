package authservice

import (
	"context"
	"testing"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSupportCredentialMaterialReadAuthorizerAllowsDeclaredCLIMaterial(t *testing.T) {
	t.Parallel()

	authorizer, err := NewSupportCredentialMaterialReadAuthorizer()
	if err != nil {
		t.Fatalf("NewSupportCredentialMaterialReadAuthorizer() error = %v", err)
	}

	fields, err := authorizer.AuthorizeCredentialMaterialRead(context.Background(), &authv1.CredentialMaterialReadPolicyRef{
		Kind:        authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_CLI_OAUTH_ACTIVE_QUERY,
		OwnerId:     "codex",
		CollectorId: "codex",
	}, []string{"account_id", "account_id"})
	if err != nil {
		t.Fatalf("AuthorizeCredentialMaterialRead() error = %v", err)
	}
	if got, want := len(fields), 1; got != want {
		t.Fatalf("fields len = %d, want %d", got, want)
	}
	if got, want := fields[0], "account_id"; got != want {
		t.Fatalf("field = %q, want %q", got, want)
	}
}

func TestSupportCredentialMaterialReadAuthorizerDeniesUndeclaredCLIMaterial(t *testing.T) {
	t.Parallel()

	authorizer, err := NewSupportCredentialMaterialReadAuthorizer()
	if err != nil {
		t.Fatalf("NewSupportCredentialMaterialReadAuthorizer() error = %v", err)
	}

	_, err = authorizer.AuthorizeCredentialMaterialRead(context.Background(), &authv1.CredentialMaterialReadPolicyRef{
		Kind:        authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_CLI_OAUTH_ACTIVE_QUERY,
		OwnerId:     "codex",
		CollectorId: "codex",
	}, []string{"access_token"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AuthorizeCredentialMaterialRead() status = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
}

func TestSupportCredentialMaterialReadAuthorizerAllowsReadableBackfillMaterial(t *testing.T) {
	t.Parallel()

	authorizer, err := NewSupportCredentialMaterialReadAuthorizer()
	if err != nil {
		t.Fatalf("NewSupportCredentialMaterialReadAuthorizer() error = %v", err)
	}

	fields, err := authorizer.AuthorizeCredentialMaterialRead(context.Background(), &authv1.CredentialMaterialReadPolicyRef{
		Kind:        authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_CLI_OAUTH_ACTIVE_QUERY,
		OwnerId:     "gemini-cli",
		CollectorId: "gemini-cli",
	}, []string{"project_id", "tier_name"})
	if err != nil {
		t.Fatalf("AuthorizeCredentialMaterialRead() error = %v", err)
	}
	if got, want := len(fields), 2; got != want {
		t.Fatalf("fields len = %d, want %d", got, want)
	}
}

func TestSupportCredentialMaterialReadAuthorizerAllowsDeclaredVendorMaterial(t *testing.T) {
	t.Parallel()

	authorizer, err := NewSupportCredentialMaterialReadAuthorizer()
	if err != nil {
		t.Fatalf("NewSupportCredentialMaterialReadAuthorizer() error = %v", err)
	}

	_, err = authorizer.AuthorizeCredentialMaterialRead(context.Background(), &authv1.CredentialMaterialReadPolicyRef{
		Kind:        authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_VENDOR_ACTIVE_QUERY,
		OwnerId:     "google",
		SurfaceId:   "gemini",
		CollectorId: "google-aistudio-quotas",
	}, []string{"project_id"})
	if err != nil {
		t.Fatalf("AuthorizeCredentialMaterialRead() error = %v", err)
	}
}

func TestSupportCredentialMaterialReadAuthorizerDeniesVendorSecretMaterial(t *testing.T) {
	t.Parallel()

	authorizer, err := NewSupportCredentialMaterialReadAuthorizer()
	if err != nil {
		t.Fatalf("NewSupportCredentialMaterialReadAuthorizer() error = %v", err)
	}

	_, err = authorizer.AuthorizeCredentialMaterialRead(context.Background(), &authv1.CredentialMaterialReadPolicyRef{
		Kind:        authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_VENDOR_ACTIVE_QUERY,
		OwnerId:     "google",
		SurfaceId:   "gemini",
		CollectorId: "google-aistudio-quotas",
	}, []string{"cookie"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AuthorizeCredentialMaterialRead() status = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
}
