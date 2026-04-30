package credentialpolicy

import (
	"context"
	"strings"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
	vendorsupport "code-code.internal/platform-k8s/internal/platform/vendors/support"
	"google.golang.org/protobuf/proto"
)

type SessionInputFormResolver struct {
	vendors *vendorsupport.ManagementService
}

func NewSessionInputFormResolver() (*SessionInputFormResolver, error) {
	vendors, err := vendorsupport.NewManagementService()
	if err != nil {
		return nil, err
	}
	return &SessionInputFormResolver{vendors: vendors}, nil
}

func (r *SessionInputFormResolver) ResolveSessionInputForm(ctx context.Context, schemaID string) (*observabilityv1.ActiveQueryInputForm, bool, error) {
	schemaID = strings.TrimSpace(schemaID)
	if schemaID == "" || r == nil || r.vendors == nil {
		return nil, false, nil
	}
	vendors, err := r.vendors.List(ctx)
	if err != nil {
		return nil, false, err
	}
	for _, vendor := range vendors {
		for _, binding := range vendor.GetProviderBindings() {
			for _, profile := range binding.GetObservability().GetProfiles() {
				form := profile.GetActiveQuery().GetInputForm()
				if form == nil || strings.TrimSpace(form.GetSchemaId()) != schemaID {
					continue
				}
				return proto.Clone(form).(*observabilityv1.ActiveQueryInputForm), true, nil
			}
		}
	}
	return nil, false, nil
}
