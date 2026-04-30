package support

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
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

func materializeVendorYAML(vendorID string) (*supportv1.Vendor, error) {
	vendorID = strings.TrimSpace(vendorID)
	if vendorID == "" {
		return nil, fmt.Errorf("platformk8s: vendor support id is empty")
	}
	raw, err := staticVendorYAMLFS.ReadFile("vendors/" + vendorID + ".yaml")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("platformk8s: vendor support %q not found", vendorID)
		}
		return nil, err
	}
	asJSON, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("platformk8s: decode vendor support yaml %q: %w", vendorID, err)
	}
	item := &supportv1.Vendor{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(asJSON, item); err != nil {
		return nil, fmt.Errorf("platformk8s: decode vendor support proto %q: %w", vendorID, err)
	}
	return item, nil
}
