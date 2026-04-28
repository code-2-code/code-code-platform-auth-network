package egressservice

import (
	"context"
	"fmt"
	"strings"

	egressservicev1 "code-code.internal/go-contract/platform/egress/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	"code-code.internal/platform-k8s/internal/egressservice/egresspolicies"
	"code-code.internal/platform-k8s/internal/egressservice/runtimeobservability"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// Config wires platform-egress-service to Kubernetes-backed egress policy storage.
type Config struct {
	Client                         ctrlclient.Client
	Reader                         ctrlclient.Reader
	Namespace                      string
	EgressNamespace                string
	DynamicHeaderAuthzProviderName string
	RuntimeTelemetry               runtimeobservability.Config
}

type Server struct {
	egressservicev1.UnimplementedEgressServiceServer

	policies         *egresspolicies.Service
	runtimeTelemetry *runtimeobservability.Reconciler
}

func NewServer(config Config) (*Server, error) {
	if config.Reader == nil {
		return nil, fmt.Errorf("platformk8s/egressservice: reader is nil")
	}
	if config.Client == nil {
		return nil, fmt.Errorf("platformk8s/egressservice: client is nil")
	}
	if strings.TrimSpace(config.Namespace) == "" {
		return nil, fmt.Errorf("platformk8s/egressservice: namespace is empty")
	}
	policies, err := egresspolicies.NewService(egresspolicies.ServiceConfig{
		Client:    config.Client,
		Reader:    config.Reader,
		Namespace: config.Namespace,
		EgressRuntime: egresspolicies.EgressRuntimeConfig{
			Namespace:                      config.EgressNamespace,
			DynamicHeaderAuthzProviderName: config.DynamicHeaderAuthzProviderName,
		},
	})
	if err != nil {
		return nil, err
	}
	runtimeTelemetryConfig := config.RuntimeTelemetry
	if runtimeTelemetryConfig.Client == nil {
		runtimeTelemetryConfig.Client = config.Client
	}
	if strings.TrimSpace(runtimeTelemetryConfig.NetworkNamespace) == "" {
		runtimeTelemetryConfig.NetworkNamespace = config.EgressNamespace
	}
	runtimeTelemetry, err := runtimeobservability.NewReconciler(runtimeTelemetryConfig)
	if err != nil {
		return nil, err
	}
	return &Server{
		policies:         policies,
		runtimeTelemetry: runtimeTelemetry,
	}, nil
}

func (s *Server) RunRuntimeTelemetryReconciler(ctx context.Context) {
	if s == nil || s.runtimeTelemetry == nil {
		return
	}
	s.runtimeTelemetry.Run(ctx)
}

func (s *Server) ListEgressPolicies(ctx context.Context, _ *managementv1.ListEgressPoliciesRequest) (*managementv1.ListEgressPoliciesResponse, error) {
	items, err := s.policies.List(ctx)
	if err != nil {
		return nil, err
	}
	return &managementv1.ListEgressPoliciesResponse{Items: items}, nil
}

func (s *Server) UpdateEgressPolicy(ctx context.Context, request *managementv1.UpdateEgressPolicyRequest) (*managementv1.UpdateEgressPolicyResponse, error) {
	item, err := s.policies.Update(ctx, request.GetPolicy())
	if err != nil {
		return nil, err
	}
	return &managementv1.UpdateEgressPolicyResponse{Item: item}, nil
}

func (s *Server) ApplyExternalAccessSet(ctx context.Context, request *egressservicev1.ApplyExternalAccessSetRequest) (*egressservicev1.ApplyExternalAccessSetResponse, error) {
	result, err := s.policies.ApplyExternalAccessSet(ctx, request.GetAccessSet())
	if err != nil {
		return nil, err
	}
	return &egressservicev1.ApplyExternalAccessSetResponse{
		Item:                       result.Item,
		AddedExternalRuleCount:     result.Added,
		UpdatedExternalRuleCount:   result.Updated,
		RemovedExternalRuleCount:   result.Removed,
		UnchangedExternalRuleCount: result.Unchanged,
	}, nil
}

func (s *Server) DeleteExternalAccessSet(ctx context.Context, request *egressservicev1.DeleteExternalAccessSetRequest) (*egressservicev1.DeleteExternalAccessSetResponse, error) {
	result, err := s.policies.DeleteExternalAccessSet(ctx, request.GetPolicyId(), request.GetAccessSetId())
	if err != nil {
		return nil, err
	}
	return &egressservicev1.DeleteExternalAccessSetResponse{
		Item:                     result.Item,
		RemovedExternalRuleCount: result.RemovedExternalRule,
		RemovedServiceRuleCount:  result.RemovedServiceRule,
		RemovedHttpRouteCount:    result.RemovedHTTPRoute,
	}, nil
}

func (s *Server) GetEgressRuntimePolicy(_ context.Context, request *egressservicev1.GetEgressRuntimePolicyRequest) (*egressservicev1.GetEgressRuntimePolicyResponse, error) {
	policy, err := s.policies.ResolveRuntimePolicy(request.GetPolicyId(), request.GetRuntimeUrl())
	if err != nil {
		return nil, err
	}
	return &egressservicev1.GetEgressRuntimePolicyResponse{Policy: policy}, nil
}

func (s *Server) ApplyRuntimeTelemetryProfileSet(ctx context.Context, request *egressservicev1.ApplyRuntimeTelemetryProfileSetRequest) (*egressservicev1.ApplyRuntimeTelemetryProfileSetResponse, error) {
	result, err := s.runtimeTelemetry.ApplyRuntimeTelemetryProfileSet(ctx, runtimeobservability.ApplyRuntimeTelemetryProfileSetCommand{
		ProfileSetID: strings.TrimSpace(request.GetProfileSetId()),
		Capability:   request.GetCapability(),
	})
	if err != nil {
		return nil, err
	}
	return &egressservicev1.ApplyRuntimeTelemetryProfileSetResponse{
		Applied:      result.Applied,
		ProfileCount: result.ProfileCount,
	}, nil
}
