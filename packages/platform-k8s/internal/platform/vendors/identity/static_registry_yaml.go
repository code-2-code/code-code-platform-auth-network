package identity

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	vendordefinitionv1 "code-code.internal/go-contract/vendor_definition/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

//go:embed vendors/*.yaml
var staticVendorYAMLFS embed.FS

func staticVendorYAMLIDs() []string {
	entries, err := fs.Glob(staticVendorYAMLFS, "vendors/*.yaml")
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		id := strings.TrimSuffix(filepath.Base(entry), filepath.Ext(entry))
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func materializeVendorDefinitionYAML(vendorID string) (*vendordefinitionv1.Vendor, error) {
	vendorID = strings.TrimSpace(vendorID)
	if vendorID == "" {
		return nil, fmt.Errorf("platformk8s: vendor definition id is empty")
	}
	raw, err := staticVendorYAMLFS.ReadFile("vendors/" + vendorID + ".yaml")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("platformk8s: vendor definition %q not found", vendorID)
		}
		return nil, err
	}
	asJSON, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: decode vendor definition yaml %q: %w", vendorID, err)
	}
	item := &vendordefinitionv1.Vendor{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(asJSON, item); err != nil {
		return nil, fmt.Errorf("platformk8s: decode vendor definition proto %q: %w", vendorID, err)
	}
	if item.VendorId == "" {
		item.VendorId = vendorID
	}
	return item, nil
}
