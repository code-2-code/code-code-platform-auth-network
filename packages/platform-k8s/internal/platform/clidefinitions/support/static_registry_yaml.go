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

//go:embed clis/*.yaml
var staticCLIYAMLFS embed.FS

func staticCLIYAMLIDs() []string {
	entries, err := fs.Glob(staticCLIYAMLFS, "clis/*.yaml")
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

func materializeRegisteredCLIYAML(cliID string) (*supportv1.CLI, bool, error) {
	cliID = strings.TrimSpace(cliID)
	if cliID == "" {
		return nil, false, nil
	}
	raw, err := staticCLIYAMLFS.ReadFile("clis/" + cliID + ".yaml")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	asJSON, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return nil, true, fmt.Errorf("platformk8s: decode cli support yaml %q: %w", cliID, err)
	}
	item := &supportv1.CLI{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(asJSON, item); err != nil {
		return nil, true, fmt.Errorf("platformk8s: decode cli support proto yaml %q: %w", cliID, err)
	}
	return item, true, nil
}
