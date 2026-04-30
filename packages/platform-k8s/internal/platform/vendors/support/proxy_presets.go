package support

import (
	"bytes"
	"embed"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
	"gopkg.in/yaml.v3"
)

//go:embed proxy_presets.yaml
var proxyPresetFS embed.FS

type proxyPresetFile struct {
	ProxyPresets []proxyPresetConfig `yaml:"proxyPresets"`
}

type proxyPresetConfig struct {
	PresetID      string `yaml:"presetId"`
	DisplayName   string `yaml:"displayName"`
	OwnerService  string `yaml:"ownerService"`
	PolicyID      string `yaml:"policyId"`
	ProxyProtocol string `yaml:"proxyProtocol"`
	DestinationID string `yaml:"destinationId"`
	HostExact     string `yaml:"hostExact"`
	HostWildcard  string `yaml:"hostWildcard"`
	AddressCIDR   string `yaml:"addressCidr"`
	Port          int32  `yaml:"port"`
}

var presetProxyConfigs = mustLoadProxyPresets()

func PresetProxyAccessSets() []*egressv1.ExternalAccessSet {
	out := make([]*egressv1.ExternalAccessSet, 0, len(presetProxyConfigs))
	for _, preset := range presetProxyConfigs {
		out = append(out, externalAccessSetFromProxyPreset(preset))
	}
	return out
}

func mustLoadProxyPresets() []proxyPresetConfig {
	payload, err := proxyPresetFS.ReadFile("proxy_presets.yaml")
	if err != nil {
		panic(fmt.Sprintf("platformk8s/vendors/support: read proxy presets: %v", err))
	}
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
	var file proxyPresetFile
	if err := decoder.Decode(&file); err != nil {
		panic(fmt.Sprintf("platformk8s/vendors/support: parse proxy presets: %v", err))
	}
	presets, err := normalizeProxyPresetFile(file)
	if err != nil {
		panic(fmt.Sprintf("platformk8s/vendors/support: invalid proxy presets: %v", err))
	}
	return presets
}

func normalizeProxyPresetFile(file proxyPresetFile) ([]proxyPresetConfig, error) {
	seen := map[string]struct{}{}
	presets := make([]proxyPresetConfig, 0, len(file.ProxyPresets))
	for index, preset := range file.ProxyPresets {
		normalized, err := normalizeProxyPreset(index, preset)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized.PresetID]; ok {
			return nil, fmt.Errorf("duplicate presetId %q", normalized.PresetID)
		}
		seen[normalized.PresetID] = struct{}{}
		presets = append(presets, normalized)
	}
	slices.SortFunc(presets, func(left, right proxyPresetConfig) int {
		return strings.Compare(left.PresetID, right.PresetID)
	})
	return presets, nil
}

func normalizeProxyPreset(index int, preset proxyPresetConfig) (proxyPresetConfig, error) {
	presetID := strings.TrimSpace(preset.PresetID)
	if presetID == "" {
		return proxyPresetConfig{}, fmt.Errorf("proxyPresets[%d].presetId is required", index)
	}
	displayName := strings.TrimSpace(preset.DisplayName)
	if displayName == "" {
		displayName = presetID
	}
	ownerService := strings.TrimSpace(preset.OwnerService)
	if ownerService == "" {
		return proxyPresetConfig{}, fmt.Errorf("proxy preset %q ownerService is required", presetID)
	}
	proxyProtocol := strings.TrimSpace(strings.ToLower(preset.ProxyProtocol))
	if !supportedProxyProtocol(proxyProtocol) {
		return proxyPresetConfig{}, fmt.Errorf("proxy preset %q proxyProtocol must be http-connect or socks5", presetID)
	}
	destinationID := strings.TrimSpace(preset.DestinationID)
	if destinationID == "" {
		destinationID = presetID
	}
	hostExact := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(preset.HostExact), "."))
	hostWildcard := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(preset.HostWildcard), "."))
	if hostWildcard != "" {
		return proxyPresetConfig{}, fmt.Errorf("proxy preset %q hostWildcard is not supported; proxy endpoints must be exact hosts", presetID)
	}
	if hostExact == "" {
		return proxyPresetConfig{}, fmt.Errorf("proxy preset %q hostExact is required", presetID)
	}
	addressCIDR := strings.TrimSpace(preset.AddressCIDR)
	if addressCIDR != "" {
		if _, err := netip.ParsePrefix(addressCIDR); err != nil {
			return proxyPresetConfig{}, fmt.Errorf("proxy preset %q addressCidr is invalid: %w", presetID, err)
		}
	}
	port := preset.Port
	if port < 1 || port > 65535 {
		return proxyPresetConfig{}, fmt.Errorf("proxy preset %q port must be between 1 and 65535", presetID)
	}
	return proxyPresetConfig{
		PresetID:      presetID,
		DisplayName:   displayName,
		OwnerService:  ownerService,
		PolicyID:      strings.TrimSpace(preset.PolicyID),
		ProxyProtocol: proxyProtocol,
		DestinationID: destinationID,
		HostExact:     hostExact,
		HostWildcard:  hostWildcard,
		AddressCIDR:   addressCIDR,
		Port:          port,
	}, nil
}

func supportedProxyProtocol(value string) bool {
	switch value {
	case "http-connect", "socks5":
		return true
	default:
		return false
	}
}

func externalAccessSetFromProxyPreset(preset proxyPresetConfig) *egressv1.ExternalAccessSet {
	return &egressv1.ExternalAccessSet{
		AccessSetId:  preset.PresetID,
		DisplayName:  preset.DisplayName,
		OwnerService: preset.OwnerService,
		PolicyId:     preset.PolicyID,
		ProxyEndpoints: []*egressv1.ProxyEndpoint{{
			ProxyEndpointId: preset.DestinationID,
			DisplayName:     preset.DisplayName,
			HostMatch:       hostMatchForProxyPreset(preset),
			AddressCidr:     preset.AddressCIDR,
			Port:            preset.Port,
			Protocol:        proxyProtocol(preset.ProxyProtocol),
			Resolution:      proxyPresetResolution(preset),
		}},
	}
}

func proxyProtocol(value string) egressv1.ProxyProtocol {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "socks5":
		return egressv1.ProxyProtocol_PROXY_PROTOCOL_SOCKS5
	default:
		return egressv1.ProxyProtocol_PROXY_PROTOCOL_HTTP_CONNECT
	}
}

func hostMatchForProxyPreset(preset proxyPresetConfig) *egressv1.HostMatch {
	if preset.HostWildcard != "" {
		return &egressv1.HostMatch{Kind: &egressv1.HostMatch_HostWildcard{HostWildcard: preset.HostWildcard}}
	}
	return &egressv1.HostMatch{Kind: &egressv1.HostMatch_HostExact{HostExact: preset.HostExact}}
}

func proxyPresetResolution(preset proxyPresetConfig) egressv1.EgressResolution {
	if preset.AddressCIDR != "" {
		return egressv1.EgressResolution_EGRESS_RESOLUTION_NONE
	}
	return egressv1.EgressResolution_EGRESS_RESOLUTION_DNS
}
