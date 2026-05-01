package support

import (
	"context"
	"fmt"
	"slices"
	"strings"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
	vendordefinitionv1 "code-code.internal/go-contract/vendor_definition/v1"
	vendoridentity "code-code.internal/platform-k8s/internal/platform/vendors/identity"
	"google.golang.org/protobuf/proto"
)

// ManagementService provides read-only access to registered
// vendor capabilities.
type ManagementService struct {
}

// NewManagementService creates one vendor support registry
// reader.
func NewManagementService() (*ManagementService, error) {
	return &ManagementService{}, nil
}

func (s *ManagementService) List(ctx context.Context) ([]*supportv1.Vendor, error) {
	vendors, err := vendoridentity.LoadIndex(ctx)
	if err != nil {
		return nil, err
	}

	vendorIDs := staticVendorYAMLIDs()
	slices.Sort(vendorIDs)

	items := make([]*supportv1.Vendor, 0, len(vendorIDs))
	for _, vendorID := range vendorIDs {
		vendor := vendors.Get(vendorID)
		if vendor == nil {
			continue
		}
		pkg, err := materializeRegisteredVendor(vendorID, vendor)
		if err != nil {
			return nil, err
		}
		items = append(items, pkg)
	}
	slices.SortFunc(items, func(left, right *supportv1.Vendor) int {
		leftName := left.GetVendor().GetDisplayName()
		if leftName == "" {
			leftName = left.GetVendor().GetVendorId()
		}
		rightName := right.GetVendor().GetDisplayName()
		if rightName == "" {
			rightName = right.GetVendor().GetVendorId()
		}
		if leftName < rightName {
			return -1
		}
		if leftName > rightName {
			return 1
		}
		return 0
	})
	return items, nil
}

func (s *ManagementService) ListForConnect(ctx context.Context) ([]*supportv1.Vendor, error) {
	return s.List(ctx)
}

func (s *ManagementService) Get(ctx context.Context, vendorID string) (*supportv1.Vendor, error) {
	vendorID = strings.TrimSpace(vendorID)
	if vendorID == "" {
		return nil, fmt.Errorf("platformk8s: vendor support id is empty")
	}
	vendors, err := vendoridentity.LoadIndex(ctx)
	if err != nil {
		return nil, err
	}
	return materializeRegisteredVendor(vendorID, vendors.Get(vendorID))
}

func (s *ManagementService) GetForConnect(ctx context.Context, vendorID string) (*supportv1.Vendor, error) {
	return s.Get(ctx, vendorID)
}

func materializeRegisteredVendor(
	vendorID string,
	vendor *vendordefinitionv1.Vendor,
) (*supportv1.Vendor, error) {
	pkg, err := materializeVendorYAML(strings.TrimSpace(vendorID))
	if err != nil {
		return nil, err
	}
	next := proto.Clone(pkg).(*supportv1.Vendor)
	if vendor == nil {
		return nil, fmt.Errorf("platformk8s: vendor definition %q not found", vendorID)
	}
	next.Vendor = proto.Clone(vendor).(*vendordefinitionv1.Vendor)
	normalizeSurfaces(next)
	return next, nil
}
