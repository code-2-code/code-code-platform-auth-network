package authservice

import (
	"fmt"

	credentialcontract "code-code.internal/platform-contract/credential"
)

// OAuthAuthorizerRegistry dispatches OAuth authorization requests to
// cli-specific authorizer implementations based on cli_id.
type OAuthAuthorizerRegistry struct {
	codeFlowAuthorizers   map[credentialcontract.OAuthCLIID]credentialcontract.OAuthAuthorizer
	deviceFlowAuthorizers map[credentialcontract.OAuthCLIID]credentialcontract.DeviceAuthorizer
	importer              credentialcontract.OAuthCredentialImporter
}

// NewOAuthAuthorizerRegistry creates one authorizer registry.
func NewOAuthAuthorizerRegistry(importer credentialcontract.OAuthCredentialImporter) *OAuthAuthorizerRegistry {
	return &OAuthAuthorizerRegistry{
		codeFlowAuthorizers:   make(map[credentialcontract.OAuthCLIID]credentialcontract.OAuthAuthorizer),
		deviceFlowAuthorizers: make(map[credentialcontract.OAuthCLIID]credentialcontract.DeviceAuthorizer),
		importer:              importer,
	}
}

// RegisterCodeFlow registers one code-flow authorizer for a cli_id.
func (r *OAuthAuthorizerRegistry) RegisterCodeFlow(cliID credentialcontract.OAuthCLIID, authorizer credentialcontract.OAuthAuthorizer) {
	r.codeFlowAuthorizers[cliID] = authorizer
}

func (r *OAuthAuthorizerRegistry) RegisterDeviceFlow(cliID credentialcontract.OAuthCLIID, authorizer credentialcontract.DeviceAuthorizer) {
	r.deviceFlowAuthorizers[cliID] = authorizer
}

// CodeFlowAuthorizer returns the code-flow authorizer for the given cli_id.
func (r *OAuthAuthorizerRegistry) CodeFlowAuthorizer(cliID credentialcontract.OAuthCLIID) (credentialcontract.OAuthAuthorizer, error) {
	authorizer, ok := r.codeFlowAuthorizers[cliID]
	if !ok {
		return nil, fmt.Errorf("platformk8s/authservice: unsupported code-flow oauth cli %q", cliID)
	}
	return authorizer, nil
}

func (r *OAuthAuthorizerRegistry) DeviceFlowAuthorizer(cliID credentialcontract.OAuthCLIID) (credentialcontract.DeviceAuthorizer, error) {
	authorizer, ok := r.deviceFlowAuthorizers[cliID]
	if !ok {
		return nil, fmt.Errorf("platformk8s/authservice: unsupported device-flow oauth cli %q", cliID)
	}
	return authorizer, nil
}

// Importer returns the shared credential importer.
func (r *OAuthAuthorizerRegistry) Importer() credentialcontract.OAuthCredentialImporter {
	return r.importer
}
