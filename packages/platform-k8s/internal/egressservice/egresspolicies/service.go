package egresspolicies

import (
	"context"
	"fmt"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
	egressservicev1 "code-code.internal/go-contract/platform/egress/v1"
	managementv1 "code-code.internal/go-contract/platform/management/v1"
	"google.golang.org/protobuf/proto"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type Service struct {
	client        ctrlclient.Client
	reader        ctrlclient.Reader
	namespace     string
	egressRuntime egressRuntime
	runtimePolicy *runtimePolicyCatalog
}

type ServiceConfig struct {
	Client        ctrlclient.Client
	Reader        ctrlclient.Reader
	Namespace     string
	EgressRuntime EgressRuntimeConfig
}

type ApplyExternalAccessSetResult struct {
	Item      *managementv1.EgressPolicyView
	Added     int32
	Updated   int32
	Removed   int32
	Unchanged int32
}

type DeleteExternalAccessSetResult struct {
	Item                *managementv1.EgressPolicyView
	RemovedExternalRule int32
	RemovedServiceRule  int32
	RemovedHTTPRoute    int32
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Reader == nil {
		return nil, fmt.Errorf("platformk8s/egressservice/egresspolicies: reader is nil")
	}
	if strings.TrimSpace(config.Namespace) == "" {
		return nil, fmt.Errorf("platformk8s/egressservice/egresspolicies: namespace is empty")
	}
	egressRuntime, err := newEgressRuntime(config.EgressRuntime)
	if err != nil {
		return nil, err
	}
	runtimePolicy, err := loadRuntimePolicyCatalog()
	if err != nil {
		return nil, err
	}
	return &Service{
		client:        config.Client,
		reader:        config.Reader,
		namespace:     strings.TrimSpace(config.Namespace),
		egressRuntime: egressRuntime,
		runtimePolicy: runtimePolicy,
	}, nil
}

func (s *Service) List(ctx context.Context) ([]*managementv1.EgressPolicyView, error) {
	policy, err := s.loadPolicy(ctx)
	if err != nil {
		return nil, err
	}
	refs, err := s.currentResourceRefs(ctx)
	if err != nil {
		return nil, err
	}
	return []*managementv1.EgressPolicyView{s.view(policy, refs)}, nil
}

func (s *Service) Update(ctx context.Context, policy *egressv1.EgressPolicy) (*managementv1.EgressPolicyView, error) {
	if s.client == nil {
		return nil, fmt.Errorf("platformk8s/egressservice/egresspolicies: client is nil")
	}
	normalized, err := normalizePolicy(policy)
	if err != nil {
		return nil, err
	}
	return s.applyPolicy(ctx, normalized)
}

func (s *Service) ApplyExternalAccessSet(ctx context.Context, accessSet *egressv1.ExternalAccessSet) (*ApplyExternalAccessSetResult, error) {
	if s.client == nil {
		return nil, fmt.Errorf("platformk8s/egressservice/egresspolicies: client is nil")
	}
	current, err := s.loadPolicy(ctx)
	if err != nil {
		return nil, err
	}
	normalizedSet, err := normalizeAccessSet(accessSet, current.GetPolicyId())
	if err != nil {
		return nil, err
	}
	if len(normalizedSet.GetExternalRules()) == 0 && len(normalizedSet.GetServiceRules()) == 0 && len(normalizedSet.GetHttpRoutes()) == 0 {
		return nil, fmt.Errorf("external access set %q is empty; use DeleteExternalAccessSet to remove an existing set", normalizedSet.GetAccessSetId())
	}
	next := proto.Clone(current).(*egressv1.EgressPolicy)
	beforeSet := replaceAccessSet(next, normalizedSet)
	normalizedPolicy, err := normalizePolicy(next)
	if err != nil {
		return nil, err
	}
	item, err := s.applyPolicy(ctx, normalizedPolicy)
	if err != nil {
		return nil, err
	}
	diff := diffAccessSet(beforeSet, normalizedSet)
	return &ApplyExternalAccessSetResult{
		Item:      item,
		Added:     diff.added,
		Updated:   diff.updated,
		Removed:   diff.removed,
		Unchanged: diff.unchanged,
	}, nil
}

func (s *Service) DeleteExternalAccessSet(ctx context.Context, policyID string, accessSetID string) (*DeleteExternalAccessSetResult, error) {
	if s.client == nil {
		return nil, fmt.Errorf("platformk8s/egressservice/egresspolicies: client is nil")
	}
	accessSetID = strings.TrimSpace(accessSetID)
	if accessSetID == "" {
		return nil, fmt.Errorf("external access set id is empty")
	}
	current, err := s.loadPolicy(ctx)
	if err != nil {
		return nil, err
	}
	policyID = strings.TrimSpace(policyID)
	if policyID != "" && policyID != current.GetPolicyId() {
		return nil, fmt.Errorf("egress policy %q does not match current policy %q", policyID, current.GetPolicyId())
	}
	next := proto.Clone(current).(*egressv1.EgressPolicy)
	removed := removeAccessSet(next, accessSetID)
	normalizedPolicy, err := normalizePolicy(next)
	if err != nil {
		return nil, err
	}
	item, err := s.applyPolicy(ctx, normalizedPolicy)
	if err != nil {
		return nil, err
	}
	result := &DeleteExternalAccessSetResult{Item: item}
	if removed != nil {
		result.RemovedExternalRule = int32(len(removed.GetExternalRules()))
		result.RemovedServiceRule = int32(len(removed.GetServiceRules()))
		result.RemovedHTTPRoute = int32(len(removed.GetHttpRoutes()))
	}
	return result, nil
}

func (s *Service) ResolveRuntimePolicy(policyID string, runtimeURL string) (*egressservicev1.EgressRuntimePolicy, error) {
	if s.runtimePolicy == nil {
		return nil, fmt.Errorf("platformk8s/egressservice/egresspolicies: runtime policy catalog is unavailable")
	}
	return s.runtimePolicy.resolve(policyID, runtimeURL)
}

func (s *Service) applyPolicy(ctx context.Context, policy *egressv1.EgressPolicy) (*managementv1.EgressPolicyView, error) {
	desired, err := desiredStateFromPolicy(policy)
	if err != nil {
		return nil, err
	}
	objects := desiredObjects(s.egressRuntime, desired)
	if err := s.savePolicy(ctx, policy); err != nil {
		return nil, err
	}
	if err := s.applyGeneratedObjects(ctx, objects); err != nil {
		return nil, err
	}
	return s.view(policy, resourceRefsFromObjects(objects)), nil
}

func (s *Service) view(policy *egressv1.EgressPolicy, refs []*egressv1.EgressResourceRef) *managementv1.EgressPolicyView {
	return &managementv1.EgressPolicyView{
		Policy:       policy,
		ConfiguredBy: sourceView("service", policyID, policyDisplayName, "ConfigMap"),
		Sync:         syncStatus(s.egressRuntime, refs),
	}
}

func sourceView(kind string, id string, displayName string, crdKind string) *managementv1.EgressConfigSource {
	return &managementv1.EgressConfigSource{
		Kind:        kind,
		Id:          id,
		DisplayName: displayName,
		CrdKind:     crdKind,
	}
}

func replaceAccessSet(policy *egressv1.EgressPolicy, accessSet *egressv1.ExternalAccessSet) *egressv1.ExternalAccessSet {
	var previous *egressv1.ExternalAccessSet
	replaced := false
	for index, existing := range policy.GetAccessSets() {
		if existing.GetAccessSetId() != accessSet.GetAccessSetId() {
			continue
		}
		previous = existing
		policy.AccessSets[index] = accessSet
		replaced = true
		break
	}
	if !replaced {
		policy.AccessSets = append(policy.AccessSets, accessSet)
	}
	return previous
}

func removeAccessSet(policy *egressv1.EgressPolicy, accessSetID string) *egressv1.ExternalAccessSet {
	accessSetID = strings.TrimSpace(accessSetID)
	for index, existing := range policy.GetAccessSets() {
		if existing.GetAccessSetId() != accessSetID {
			continue
		}
		policy.AccessSets = append(policy.AccessSets[:index], policy.AccessSets[index+1:]...)
		return existing
	}
	return nil
}
