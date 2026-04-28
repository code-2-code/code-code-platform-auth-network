package cliversions

import (
	"fmt"
	"strings"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

type SourceKind string

const (
	SourceKindNPMRegistry  SourceKind = "npm_dist_tag"
	SourceKindHomebrewCask SourceKind = "homebrew_cask"
)

type Source struct {
	Kind        SourceKind
	CLIID       string
	PackageName string
	DistTag     string
	Cask        string
}

func ResolveSource(cli *supportv1.CLI) (Source, bool, error) {
	if cli == nil {
		return Source{}, false, nil
	}
	source := cli.GetOfficialVersionSource()
	if source == nil {
		return Source{}, false, nil
	}
	resolved := Source{
		CLIID: strings.TrimSpace(cli.GetCliId()),
	}
	switch typed := source.GetSource().(type) {
	case *supportv1.OfficialVersionSource_NpmDistTag:
		resolved.Kind = SourceKindNPMRegistry
		resolved.PackageName = strings.TrimSpace(typed.NpmDistTag.GetPackageName())
		resolved.DistTag = strings.TrimSpace(typed.NpmDistTag.GetDistTag())
		if resolved.DistTag == "" {
			resolved.DistTag = "latest"
		}
		if resolved.PackageName == "" {
			return Source{}, false, fmt.Errorf("platformk8s/cliversions: npm package name is empty")
		}
		return resolved, true, nil
	case *supportv1.OfficialVersionSource_HomebrewCask:
		resolved.Kind = SourceKindHomebrewCask
		resolved.Cask = strings.TrimSpace(typed.HomebrewCask.GetCask())
		if resolved.Cask == "" {
			return Source{}, false, fmt.Errorf("platformk8s/cliversions: homebrew cask is empty")
		}
		return resolved, true, nil
	default:
		return Source{}, false, fmt.Errorf("platformk8s/cliversions: official version source is unsupported")
	}
}
