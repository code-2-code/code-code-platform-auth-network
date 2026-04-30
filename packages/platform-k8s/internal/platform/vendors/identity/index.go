package identity

import (
	"context"
	"strings"

	vendordefinitionv1 "code-code.internal/go-contract/vendor_definition/v1"
	"google.golang.org/protobuf/proto"
)

type DefinitionIndex struct {
	items map[string]*vendordefinitionv1.Vendor
}

func LoadIndex(ctx context.Context) (DefinitionIndex, error) {
	_ = ctx
	vendorIDs := staticVendorYAMLIDs()
	index := DefinitionIndex{items: map[string]*vendordefinitionv1.Vendor{}}
	for _, vendorID := range vendorIDs {
		vendor, err := materializeRegisteredVendor(vendorID)
		if err != nil {
			continue
		}
		vendorID := strings.TrimSpace(vendor.GetVendorId())
		if vendorID == "" {
			continue
		}
		index.items[vendorID] = proto.Clone(vendor).(*vendordefinitionv1.Vendor)
	}
	return index, nil
}

func (i DefinitionIndex) Get(vendorID string) *vendordefinitionv1.Vendor {
	if len(i.items) == 0 {
		return nil
	}
	vendor := i.items[strings.TrimSpace(vendorID)]
	if vendor == nil {
		return nil
	}
	return proto.Clone(vendor).(*vendordefinitionv1.Vendor)
}
