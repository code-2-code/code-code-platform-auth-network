package oauth

import (
	"sort"
	"strings"

	credentialcontract "code-code.internal/platform-contract/credential"
	"code-code.internal/platform-k8s/internal/platform/outboundhttp"
)

type CodeFlowAuthorizerFactoryConfig struct {
	SessionStore      *OAuthSessionStore
	HTTPClientFactory outboundhttp.ClientFactory
}

type codeFlowAuthorizerFactory func(config CodeFlowAuthorizerFactoryConfig) (credentialcontract.OAuthAuthorizer, error)

var codeFlowAuthorizerFactories = map[string]codeFlowAuthorizerFactory{}

func registerCodeFlowAuthorizerFactory(cliID string, factory codeFlowAuthorizerFactory) {
	trimmedCLIID := strings.TrimSpace(cliID)
	if trimmedCLIID == "" || factory == nil {
		return
	}
	codeFlowAuthorizerFactories[trimmedCLIID] = factory
}

func RegisteredCodeFlowAuthorizers(config CodeFlowAuthorizerFactoryConfig) (map[credentialcontract.OAuthCLIID]credentialcontract.OAuthAuthorizer, error) {
	cliIDs := make([]string, 0, len(codeFlowAuthorizerFactories))
	for cliID := range codeFlowAuthorizerFactories {
		cliIDs = append(cliIDs, cliID)
	}
	sort.Strings(cliIDs)
	authorizers := make(map[credentialcontract.OAuthCLIID]credentialcontract.OAuthAuthorizer, len(cliIDs))
	for _, cliID := range cliIDs {
		factory := codeFlowAuthorizerFactories[cliID]
		if factory == nil {
			continue
		}
		authorizer, err := factory(config)
		if err != nil {
			return nil, err
		}
		if authorizer != nil {
			authorizers[credentialcontract.OAuthCLIID(cliID)] = authorizer
		}
	}
	return authorizers, nil
}
