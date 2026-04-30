package oauth

import (
	"fmt"
	"net/url"
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

const defaultLocalhostListenHost = "127.0.0.1"

// OAuthCallbackContract describes the effective callback-delivery contract of
// one CLI OAuth code flow after hosted redirect derivation is applied.
type OAuthCallbackContract struct {
	Mode                  credentialv1.OAuthCallbackMode
	CallbackProviderID    string
	ProviderRedirectURI   string
	LocalhostListenHost   string
	LocalhostListenPort   uint32
	LocalhostCallbackPath string
}

// ResolveOAuthCallbackContract returns the effective callback-delivery
// contract declared by one CLI package.
func ResolveOAuthCallbackContract(pkg *supportv1.CLI, hostedCallbackBaseURL string) (*OAuthCallbackContract, error) {
	if pkg == nil || pkg.GetOauth() == nil || pkg.GetOauth().GetCodeFlow() == nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: cli oauth code flow is nil")
	}
	delivery := pkg.GetOauth().GetCodeFlow().GetCallbackDelivery()
	if delivery == nil {
		return nil, fmt.Errorf("platformk8s/clidefinitions: cli oauth callback delivery is nil")
	}

	contract := &OAuthCallbackContract{
		Mode:                  delivery.GetMode(),
		CallbackProviderID:    strings.TrimSpace(delivery.GetCallbackProviderId()),
		ProviderRedirectURI:   strings.TrimSpace(delivery.GetProviderRedirectUri()),
		LocalhostListenHost:   strings.TrimSpace(delivery.GetLocalhostListenHost()),
		LocalhostListenPort:   delivery.GetLocalhostListenPort(),
		LocalhostCallbackPath: strings.TrimSpace(delivery.GetLocalhostCallbackPath()),
	}

	switch contract.Mode {
	case credentialv1.OAuthCallbackMode_O_AUTH_CALLBACK_MODE_HOSTED_CALLBACK:
		if contract.CallbackProviderID == "" {
			return nil, fmt.Errorf("platformk8s/clidefinitions: hosted callback provider id is empty")
		}
		baseURL := strings.TrimSpace(hostedCallbackBaseURL)
		if baseURL == "" {
			return nil, fmt.Errorf("platformk8s/clidefinitions: hosted callback base url is empty")
		}
		parsed, err := url.Parse(baseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("platformk8s/clidefinitions: hosted callback base url is invalid")
		}
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/oauth/callback/" + url.PathEscape(contract.CallbackProviderID)
		parsed.RawQuery = ""
		parsed.Fragment = ""
		contract.ProviderRedirectURI = parsed.String()
	case credentialv1.OAuthCallbackMode_O_AUTH_CALLBACK_MODE_LOCALHOST_RELAY:
		if contract.CallbackProviderID == "" {
			return nil, fmt.Errorf("platformk8s/clidefinitions: localhost relay callback provider id is empty")
		}
		if contract.ProviderRedirectURI == "" {
			return nil, fmt.Errorf("platformk8s/clidefinitions: localhost relay provider redirect uri is empty")
		}
		if _, err := url.ParseRequestURI(contract.ProviderRedirectURI); err != nil {
			return nil, fmt.Errorf("platformk8s/clidefinitions: localhost relay provider redirect uri is invalid: %w", err)
		}
		if contract.LocalhostListenHost == "" {
			contract.LocalhostListenHost = defaultLocalhostListenHost
		}
		if contract.LocalhostListenPort == 0 {
			return nil, fmt.Errorf("platformk8s/clidefinitions: localhost relay listen port is empty")
		}
		if contract.LocalhostCallbackPath == "" || !strings.HasPrefix(contract.LocalhostCallbackPath, "/") {
			return nil, fmt.Errorf("platformk8s/clidefinitions: localhost relay callback path is invalid")
		}
	default:
		return nil, fmt.Errorf("platformk8s/clidefinitions: oauth callback mode is unspecified")
	}
	return contract, nil
}
