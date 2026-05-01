package credentialpolicy

import (
	"context"
	"testing"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMaterialReadAuthorizerAllowsDeclaredCLIMaterial(t *testing.T) {
	t.Parallel()

	authorizer, err := NewMaterialReadAuthorizer()
	if err != nil {
		t.Fatalf("NewMaterialReadAuthorizer() error = %v", err)
	}

	fields, err := authorizer.AuthorizeCredentialMaterialRead(context.Background(), &authv1.CredentialMaterialReadPolicyRef{
		Kind:        authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_CLI_OAUTH_QUOTA_QUERY,
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

func TestMaterialReadAuthorizerDeniesUndeclaredCLIMaterial(t *testing.T) {
	t.Parallel()

	authorizer, err := NewMaterialReadAuthorizer()
	if err != nil {
		t.Fatalf("NewMaterialReadAuthorizer() error = %v", err)
	}

	_, err = authorizer.AuthorizeCredentialMaterialRead(context.Background(), &authv1.CredentialMaterialReadPolicyRef{
		Kind:        authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_CLI_OAUTH_QUOTA_QUERY,
		OwnerId:     "codex",
		CollectorId: "codex",
	}, []string{"access_token"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AuthorizeCredentialMaterialRead() status = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
}

func TestMaterialReadAuthorizerAllowsReadableBackfillMaterial(t *testing.T) {
	t.Parallel()

	authorizer, err := NewMaterialReadAuthorizer()
	if err != nil {
		t.Fatalf("NewMaterialReadAuthorizer() error = %v", err)
	}

	fields, err := authorizer.AuthorizeCredentialMaterialRead(context.Background(), &authv1.CredentialMaterialReadPolicyRef{
		Kind:        authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_CLI_OAUTH_QUOTA_QUERY,
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

func TestMaterialReadAuthorizerAllowsDeclaredVendorMaterial(t *testing.T) {
	t.Parallel()

	authorizer, err := NewMaterialReadAuthorizer()
	if err != nil {
		t.Fatalf("NewMaterialReadAuthorizer() error = %v", err)
	}

	_, err = authorizer.AuthorizeCredentialMaterialRead(context.Background(), &authv1.CredentialMaterialReadPolicyRef{
		Kind:        authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_VENDOR_QUOTA_QUERY,
		OwnerId:     "google",
		SurfaceId:   "google-gemini",
		CollectorId: "google-aistudio-quotas",
	}, []string{"project_id"})
	if err != nil {
		t.Fatalf("AuthorizeCredentialMaterialRead() error = %v", err)
	}
}

func TestMaterialReadAuthorizerDeniesVendorSecretMaterial(t *testing.T) {
	t.Parallel()

	authorizer, err := NewMaterialReadAuthorizer()
	if err != nil {
		t.Fatalf("NewMaterialReadAuthorizer() error = %v", err)
	}

	_, err = authorizer.AuthorizeCredentialMaterialRead(context.Background(), &authv1.CredentialMaterialReadPolicyRef{
		Kind:        authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_VENDOR_QUOTA_QUERY,
		OwnerId:     "google",
		SurfaceId:   "google-gemini",
		CollectorId: "google-aistudio-quotas",
	}, []string{"cookie"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AuthorizeCredentialMaterialRead() status = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
}
