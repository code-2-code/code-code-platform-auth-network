package authservice

import (
	"context"
	"strings"

	credentialv1 "code-code.internal/go-contract/credential/v1"
	authv1 "code-code.internal/go-contract/platform/auth/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	"code-code.internal/platform-k8s/internal/authservice/credentials"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

type sessionCredentialRequest interface {
	GetCredentialId() string
	GetDisplayName() string
	GetPurpose() string
	GetVendorId() string
	GetSchemaId() string
	GetRequiredKeys() []string
	GetValues() map[string]string
	GetMergeValues() bool
}

func (s *Server) CreateSessionCredential(ctx context.Context, request *authv1.CreateSessionCredentialRequest) (*authv1.CreateSessionCredentialResponse, error) {
	view, err := s.writeSessionCredential(ctx, request, true)
	if err != nil {
		return nil, err
	}
	return &authv1.CreateSessionCredentialResponse{Credential: view}, nil
}

func (s *Server) UpdateSessionCredential(ctx context.Context, request *authv1.UpdateSessionCredentialRequest) (*authv1.UpdateSessionCredentialResponse, error) {
	view, err := s.writeSessionCredential(ctx, request, false)
	if err != nil {
		return nil, err
	}
	return &authv1.UpdateSessionCredentialResponse{Credential: view}, nil
}

func (s *Server) writeSessionCredential(ctx context.Context, request sessionCredentialRequest, create bool) (*managementv1.CredentialView, error) {
	values, requiredKeys, err := s.sessionCredentialValues(ctx, request, create)
	if err != nil {
		return nil, grpcError(err)
	}
	credential, err := credentials.NewCredential(&credentialv1.CredentialDefinition{
		CredentialId: request.GetCredentialId(),
		DisplayName:  request.GetDisplayName(),
		Purpose:      purposeValue(request.GetPurpose()),
		VendorId:     request.GetVendorId(),
		Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
		KindMetadata: &credentialv1.CredentialDefinition_SessionMetadata{
			SessionMetadata: &credentialv1.SessionMetadata{
				SchemaId:     request.GetSchemaId(),
				RequiredKeys: requiredKeys,
			},
		},
	}, &credentialv1.ResolvedCredential{
		CredentialId: request.GetCredentialId(),
		Kind:         credentialv1.CredentialKind_CREDENTIAL_KIND_SESSION,
		Material: &credentialv1.ResolvedCredential_Session{
			Session: &credentialv1.SessionCredential{
				SchemaId: request.GetSchemaId(),
				Values:   values,
			},
		},
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return s.writeCredential(ctx, request.GetCredentialId(), credential, create)
}

func (s *Server) sessionCredentialValues(ctx context.Context, request sessionCredentialRequest, create bool) (map[string]string, []string, error) {
	values := trimCredentialValues(request.GetValues())
	requiredKeys := trimCredentialKeys(request.GetRequiredKeys())
	var existing map[string]string
	if !create && request.GetMergeValues() {
		current, err := s.credentialWriter.ReadMaterialValues(ctx, request.GetCredentialId())
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, nil, err
			}
		}
		existing = trimCredentialValues(current)
	}
	if s.sessionInputForms != nil {
		form, ok, err := s.sessionInputForms.ResolveSessionInputForm(ctx, request.GetSchemaId())
		if err != nil {
			return nil, nil, err
		}
		if ok {
			values, requiredKeys, err = normalizeSessionInputValues(form, values, existing)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	if create || !request.GetMergeValues() || len(values) == 0 {
		return values, requiredKeys, nil
	}
	merged := trimCredentialValues(existing)
	for key, value := range values {
		if merged == nil {
			merged = map[string]string{}
		}
		merged[key] = value
	}
	return merged, requiredKeys, nil
}

func trimCredentialValues(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func trimCredentialKeys(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
