package egressauth

const (
	HeaderRunID                    = "x-code-code-run-id"
	HeaderSessionID                = "x-code-code-session-id"
	HeaderCLIID                    = "x-code-code-cli-id"
	HeaderVendorID                 = "x-code-code-vendor-id"
	HeaderProviderID               = "x-code-code-provider-id"
	HeaderProviderSurfaceBindingID = "code-code-provider-surface-binding-id"
	HeaderModelID                  = "x-code-code-model-id"
	HeaderEgressPolicyID           = "code-code-egress-policy-id"
	HeaderAuthPolicyID             = "code-code-auth-policy-id"
	HeaderTargetHosts              = "x-code-code-target-hosts"
	HeaderRequestHeaderNames       = "x-code-code-request-header-names"
	HeaderHeaderValuePrefix        = "x-code-code-header-value-prefix"
	HeaderAuthAdapterID            = "x-code-code-auth-adapter-id"
	HeaderRequestHeaderRulesJSON   = "x-code-code-request-header-rules-json"

	HTTPHeaderAuthorization = "authorization"
	HTTPHeaderContentType   = "content-type"
	HTTPHeaderCookie        = "cookie"
	HTTPHeaderSetCookie     = "set-cookie"
	HTTPHeaderXAPIKey       = "x-api-key"
	HTTPHeaderXGoogAPIKey   = "x-goog-api-key"

	Placeholder = "PLACEHOLDER"

	AuthAdapterDefaultID               = "default"
	AuthAdapterBearerSessionID         = "bearer-session"
	AuthAdapterSessionCookieID         = "session-cookie"
	AuthAdapterGoogleAIStudioSessionID = "google-aistudio-session"

	MaterialKeyAccessToken = "access_token"
	MaterialKeyAPIKey      = "api_key"
	MaterialKeyCookie      = "cookie"
)

func InternalHeaders() []string {
	return []string{
		HeaderRunID,
		HeaderSessionID,
		HeaderCLIID,
		HeaderVendorID,
		HeaderProviderID,
		HeaderProviderSurfaceBindingID,
		HeaderModelID,
		HeaderEgressPolicyID,
		HeaderAuthPolicyID,
		HeaderTargetHosts,
		HeaderRequestHeaderNames,
		HeaderHeaderValuePrefix,
		HeaderAuthAdapterID,
		HeaderRequestHeaderRulesJSON,
	}
}
