package authservice

import (
	"context"
	"strings"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	clisupport "code-code.internal/platform-k8s/internal/supportservice/clidefinitions/support"
	vendorsupport "code-code.internal/platform-k8s/internal/supportservice/vendors/support"
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

type supportCredentialMaterialReadAuthorizer struct {
	cliSupport    *clisupport.ManagementService
	vendorSupport *vendorsupport.ManagementService
}

func NewSupportCredentialMaterialReadAuthorizer() (CredentialMaterialReadAuthorizer, error) {
	cliSupport, err := clisupport.NewManagementService()
	if err != nil {
		return nil, err
	}
	vendorSupport, err := vendorsupport.NewManagementService()
	if err != nil {
		return nil, err
	}
	return supportCredentialMaterialReadAuthorizer{
		cliSupport:    cliSupport,
		vendorSupport: vendorSupport,
	}, nil
}

func (a supportCredentialMaterialReadAuthorizer) AuthorizeCredentialMaterialRead(
	ctx context.Context,
	policyRef *authv1.CredentialMaterialReadPolicyRef,
	fieldIDs []string,
) ([]string, error) {
	requested, err := normalizeCredentialMaterialFieldIDs(fieldIDs)
	if err != nil {
		return nil, err
	}
	allowed, err := a.allowedCredentialMaterialFields(ctx, policyRef)
	if err != nil {
		return nil, err
	}
	if len(allowed) == 0 {
		return nil, status.Error(codes.PermissionDenied, "credential material read policy has no readable fields")
	}
	for _, fieldID := range requested {
		if _, ok := allowed[fieldID]; !ok {
			return nil, status.Errorf(codes.PermissionDenied, "credential material field %q is not allowed by read policy", fieldID)
		}
	}
	return requested, nil
}

func (a supportCredentialMaterialReadAuthorizer) allowedCredentialMaterialFields(
	ctx context.Context,
	policyRef *authv1.CredentialMaterialReadPolicyRef,
) (map[string]struct{}, error) {
	if policyRef == nil || policyRef.GetKind() == authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "credential material read policy ref is required")
	}
	ownerID := strings.TrimSpace(policyRef.GetOwnerId())
	collectorID := strings.TrimSpace(policyRef.GetCollectorId())
	if ownerID == "" {
		return nil, status.Error(codes.InvalidArgument, "credential material read policy owner_id is empty")
	}
	if collectorID == "" {
		return nil, status.Error(codes.InvalidArgument, "credential material read policy collector_id is empty")
	}
	switch policyRef.GetKind() {
	case authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_CLI_OAUTH_ACTIVE_QUERY:
		return a.allowedCLIOAuthActiveQueryMaterialFields(ctx, ownerID, collectorID)
	case authv1.CredentialMaterialReadPolicyKind_CREDENTIAL_MATERIAL_READ_POLICY_KIND_VENDOR_ACTIVE_QUERY:
		surfaceID := strings.TrimSpace(policyRef.GetSurfaceId())
		if surfaceID == "" {
			return nil, status.Error(codes.InvalidArgument, "vendor credential material read policy surface_id is empty")
		}
		return a.allowedVendorActiveQueryMaterialFields(ctx, ownerID, surfaceID, collectorID)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported credential material read policy kind %v", policyRef.GetKind())
	}
}

func (a supportCredentialMaterialReadAuthorizer) allowedCLIOAuthActiveQueryMaterialFields(
	ctx context.Context,
	cliID string,
	collectorID string,
) (map[string]struct{}, error) {
	if a.cliSupport == nil {
		return nil, status.Error(codes.Unavailable, "cli support registry is unavailable")
	}
	cli, err := a.cliSupport.Get(ctx, cliID)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "cli credential material read policy %q is unavailable", cliID)
	}
	capability := cli.GetOauth().GetObservability()
	fields := activeQueryReadableMaterialFields(capability, collectorID, strings.TrimSpace(cli.GetCliId()), true)
	return materialFieldSet(fields), nil
}

func (a supportCredentialMaterialReadAuthorizer) allowedVendorActiveQueryMaterialFields(
	ctx context.Context,
	vendorID string,
	surfaceID string,
	collectorID string,
) (map[string]struct{}, error) {
	if a.vendorSupport == nil {
		return nil, status.Error(codes.Unavailable, "vendor support registry is unavailable")
	}
	vendor, err := a.vendorSupport.Get(ctx, vendorID)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "vendor credential material read policy %q is unavailable", vendorID)
	}
	capability := vendorsupport.MaterializeObservability(vendor, surfaceID)
	fields := activeQueryReadableMaterialFields(capability, collectorID, "", false)
	return materialFieldSet(fields), nil
}

func activeQueryReadableMaterialFields(
	capability *observabilityv1.ObservabilityCapability,
	collectorID string,
	defaultCollectorID string,
	useDefaultCollector bool,
) []string {
	if capability == nil {
		return nil
	}
	out := []string{}
	for _, profile := range capability.GetProfiles() {
		if profile == nil || profile.GetActiveQuery() == nil {
			continue
		}
		activeQuery := profile.GetActiveQuery()
		currentCollectorID := strings.TrimSpace(activeQuery.GetCollectorId())
		if currentCollectorID == "" && useDefaultCollector {
			currentCollectorID = strings.TrimSpace(defaultCollectorID)
		}
		if currentCollectorID == "" || currentCollectorID != collectorID {
			continue
		}
		out = append(out, activeQuery.GetMaterialReadFields()...)
		for _, rule := range activeQuery.GetCredentialBackfills() {
			if rule == nil || !rule.GetReadable() {
				continue
			}
			out = append(out, rule.GetTargetMaterialKey())
		}
	}
	return normalizeCredentialMaterialFieldIDsNoError(out)
}

func materialFieldSet(fields []string) map[string]struct{} {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		out[field] = struct{}{}
	}
	return out
}

func normalizeCredentialMaterialFieldIDs(fieldIDs []string) ([]string, error) {
	out := normalizeCredentialMaterialFieldIDsNoError(fieldIDs)
	if len(out) == 0 {
		return nil, status.Error(codes.InvalidArgument, "credential material field ids are empty")
	}
	return out, nil
}

func normalizeCredentialMaterialFieldIDsNoError(fieldIDs []string) []string {
	out := make([]string, 0, len(fieldIDs))
	seen := map[string]struct{}{}
	for _, fieldID := range fieldIDs {
		fieldID = strings.TrimSpace(fieldID)
		if fieldID == "" {
			continue
		}
		if _, ok := seen[fieldID]; ok {
			continue
		}
		seen[fieldID] = struct{}{}
		out = append(out, fieldID)
	}
	return out
}

var _ CredentialMaterialReadAuthorizer = supportCredentialMaterialReadAuthorizer{}
