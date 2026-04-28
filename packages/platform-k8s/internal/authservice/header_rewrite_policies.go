package authservice

import (
	"context"
	"fmt"

	authv1 "code-code.internal/go-contract/platform/auth/v1"
)

func (s *Server) GetEgressAuthPolicy(_ context.Context, request *authv1.GetEgressAuthPolicyRequest) (*authv1.GetEgressAuthPolicyResponse, error) {
	if s.headerRewritePolicies == nil {
		return nil, fmt.Errorf("platformk8s/authservice: header rewrite policy catalog is unavailable")
	}
	return s.headerRewritePolicies.Resolve(request), nil
}
