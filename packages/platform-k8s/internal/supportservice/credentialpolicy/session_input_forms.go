package credentialpolicy

import (
	"context"
	"strings"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
	clisupport "code-code.internal/platform-k8s/internal/platform/clidefinitions/support"
	vendorsupport "code-code.internal/platform-k8s/internal/platform/vendors/support"
	"google.golang.org/protobuf/proto"
)

type SessionInputFormResolver struct {
	cliSupport    *clisupport.ManagementService
	vendorSupport *vendorsupport.ManagementService
}

func NewSessionInputFormResolver() (*SessionInputFormResolver, error) {
	cliSupport, err := clisupport.NewManagementService()
	if err != nil {
		return nil, err
	}
	vendorSupport, err := vendorsupport.NewManagementService()
	if err != nil {
		return nil, err
	}
	return &SessionInputFormResolver{
		cliSupport:    cliSupport,
		vendorSupport: vendorSupport,
	}, nil
}

func (r *SessionInputFormResolver) ResolveSessionInputForm(ctx context.Context, schemaID string) (*observabilityv1.QuotaQueryInputForm, bool, error) {
	schemaID = strings.TrimSpace(schemaID)
	if schemaID == "" {
		return nil, false, nil
	}
	if r != nil && r.cliSupport != nil {
		clis, err := r.cliSupport.List(ctx)
		if err != nil {
			return nil, false, err
		}
		for _, cli := range clis {
			if form := quotaQueryInputFormForSchema(cli.GetOauth().GetObservability(), schemaID); form != nil {
				return form, true, nil
			}
		}
	}
	if r != nil && r.vendorSupport != nil {
		vendors, err := r.vendorSupport.List(ctx)
		if err != nil {
			return nil, false, err
		}
		for _, vendor := range vendors {
			for _, surface := range vendor.GetSurfaces() {
				if form := quotaQueryInputFormForSchema(surface.GetObservability(), schemaID); form != nil {
					return form, true, nil
				}
			}
		}
	}
	return nil, false, nil
}

func quotaQueryInputFormForSchema(
	capability *observabilityv1.ObservabilityCapability,
	schemaID string,
) *observabilityv1.QuotaQueryInputForm {
	for _, profile := range capability.GetProfiles() {
		form := profile.GetQuotaQuery().GetInputForm()
		if form == nil || strings.TrimSpace(form.GetSchemaId()) != schemaID {
			continue
		}
		return proto.Clone(form).(*observabilityv1.QuotaQueryInputForm)
	}
	return nil
}
