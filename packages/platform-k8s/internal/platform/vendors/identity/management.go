package identity

import (
	"context"
	"slices"

	managementv1 "code-code.internal/go-contract/platform/management/v1"
	vendordefinitionv1 "code-code.internal/go-contract/vendor_definition/v1"
)

// VendorManagementService provides read-only access to vendor definitions.
type VendorManagementService struct {
}

// NewVendorManagementService creates one vendor management service.
func NewVendorManagementService() (*VendorManagementService, error) {
	return &VendorManagementService{}, nil
}

// List returns all vendor definitions in UI-facing form.
func (s *VendorManagementService) List(ctx context.Context) ([]*managementv1.VendorView, error) {
	_ = ctx

	vendorIDs := staticVendorYAMLIDs()
	slices.Sort(vendorIDs)

	items := make([]*managementv1.VendorView, 0, len(vendorIDs))
	for _, vendorID := range vendorIDs {
		vendor, err := materializeRegisteredVendor(vendorID)
		if err != nil {
			return nil, err
		}
		items = append(items, vendorToView(vendor))
	}
	slices.SortFunc(items, func(a, b *managementv1.VendorView) int {
		if a.GetDisplayName() < b.GetDisplayName() {
			return -1
		}
		if a.GetDisplayName() > b.GetDisplayName() {
			return 1
		}
		return 0
	})
	return items, nil
}

func vendorToView(vendor *vendordefinitionv1.Vendor) *managementv1.VendorView {
	return &managementv1.VendorView{
		VendorId:    vendor.VendorId,
		DisplayName: vendor.DisplayName,
		IconUrl:     vendor.IconUrl,
		WebsiteUrl:  vendor.WebsiteUrl,
		Description: vendor.Description,
		Aliases:     append([]string(nil), vendor.Aliases...),
	}
}

func materializeRegisteredVendor(vendorID string) (*vendordefinitionv1.Vendor, error) {
	return materializeVendorDefinitionYAML(vendorID)
}
