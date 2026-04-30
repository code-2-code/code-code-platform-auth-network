package modelcatalogdiscovery

import (
	"encoding/json"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	"code-code.internal/go-contract/domainerror"
	modelcatalogdiscoveryv1 "code-code.internal/go-contract/model_catalog_discovery/v1"
)

func operationMethod(operation *modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation) (string, error) {
	if operation == nil {
		return "", domainerror.NewValidation("platformk8s/modelcatalogdiscovery: operation is required")
	}
	switch operation.GetMethod() {
	case modelcatalogdiscoveryv1.DiscoveryHTTPMethod_DISCOVERY_HTTP_METHOD_UNSPECIFIED,
		modelcatalogdiscoveryv1.DiscoveryHTTPMethod_DISCOVERY_HTTP_METHOD_GET:
		return http.MethodGet, nil
	case modelcatalogdiscoveryv1.DiscoveryHTTPMethod_DISCOVERY_HTTP_METHOD_POST:
		return http.MethodPost, nil
	default:
		return "", domainerror.NewValidation("platformk8s/modelcatalogdiscovery: unsupported operation method %s", operation.GetMethod().String())
	}
}

func operationURL(baseURL string, operation *modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation, dynamicValues DynamicValues) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed == nil {
		return "", domainerror.NewValidation("platformk8s/modelcatalogdiscovery: invalid base_url")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", domainerror.NewValidation("platformk8s/modelcatalogdiscovery: invalid base_url")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", domainerror.NewValidation("platformk8s/modelcatalogdiscovery: invalid base_url")
	}
	path := strings.TrimSpace(operation.GetPath())
	if path == "" {
		return "", domainerror.NewValidation("platformk8s/modelcatalogdiscovery: operation path is required")
	}
	if strings.HasPrefix(path, "/") {
		parsed.Path = path
	} else {
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/" + path
	}
	query := url.Values{}
	for _, parameter := range operation.GetQueryParameters() {
		name := strings.TrimSpace(parameter.GetName())
		if name == "" {
			return "", domainerror.NewValidation("platformk8s/modelcatalogdiscovery: operation query parameter name is empty")
		}
		value, ok, err := parameterValue(parameter, dynamicValues)
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		query.Set(name, value)
	}
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String(), nil
}

func jsonBody(operation *modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation, dynamicValues DynamicValues) ([]byte, bool, error) {
	if operation == nil || len(operation.GetJsonBodyFields()) == 0 {
		return nil, false, nil
	}
	body := map[string]string{}
	for _, parameter := range operation.GetJsonBodyFields() {
		name := strings.TrimSpace(parameter.GetName())
		if name == "" {
			return nil, false, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: operation body field name is empty")
		}
		value, ok, err := parameterValue(parameter, dynamicValues)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			continue
		}
		body[name] = value
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, false, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: encode operation body failed: %v", err)
	}
	return payload, true, nil
}

func mergeHeaders(
	base http.Header,
	operation *modelcatalogdiscoveryv1.ModelCatalogDiscoveryOperation,
	dynamicValues DynamicValues,
) (http.Header, error) {
	out := cloneHeaders(base)
	if operation == nil {
		return out, nil
	}
	for _, parameter := range operation.GetRequestHeaders() {
		name := strings.TrimSpace(parameter.GetName())
		if name == "" {
			return nil, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: operation header name is empty")
		}
		value, ok, err := parameterValue(parameter, dynamicValues)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out.Set(textproto.CanonicalMIMEHeaderKey(name), value)
	}
	return out, nil
}

func parameterValue(parameter *modelcatalogdiscoveryv1.DiscoveryParameter, dynamicValues DynamicValues) (string, bool, error) {
	if parameter == nil {
		return "", false, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: operation parameter is nil")
	}
	switch value := parameter.GetValue().(type) {
	case *modelcatalogdiscoveryv1.DiscoveryParameter_Literal:
		literal := strings.TrimSpace(value.Literal)
		if literal == "" {
			return "", false, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: operation literal is empty")
		}
		return literal, true, nil
	case *modelcatalogdiscoveryv1.DiscoveryParameter_DynamicValue:
		switch value.DynamicValue {
		case modelcatalogdiscoveryv1.DiscoveryDynamicValue_DISCOVERY_DYNAMIC_VALUE_CLIENT_VERSION:
			clientVersion := strings.TrimSpace(dynamicValues.ClientVersion)
			if clientVersion == "" {
				return "", false, nil
			}
			return clientVersion, true, nil
		case modelcatalogdiscoveryv1.DiscoveryDynamicValue_DISCOVERY_DYNAMIC_VALUE_PROJECT_ID:
			projectID := strings.TrimSpace(dynamicValues.ProjectID)
			if projectID == "" {
				return "", false, nil
			}
			return projectID, true, nil
		default:
			return "", false, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: unsupported operation dynamic value %s", value.DynamicValue.String())
		}
	default:
		return "", false, domainerror.NewValidation("platformk8s/modelcatalogdiscovery: operation value is required")
	}
}

func cloneHeaders(in http.Header) http.Header {
	if len(in) == 0 {
		return make(http.Header)
	}
	out := make(http.Header, len(in))
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}
