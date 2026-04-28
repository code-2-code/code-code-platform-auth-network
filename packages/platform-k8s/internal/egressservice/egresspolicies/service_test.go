package egresspolicies

import (
	"context"
	"testing"

	egressv1 "code-code.internal/go-contract/egress/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestApplyExternalAccessSetRejectsEmptySet(t *testing.T) {
	service := testService(t, policyConfigMap(t, defaultPolicy()))

	_, err := service.ApplyExternalAccessSet(context.Background(), &egressv1.ExternalAccessSet{
		AccessSetId: "support.external-rule-set.l7-smoke",
		PolicyId:    policyID,
	})
	if err == nil {
		t.Fatal("ApplyExternalAccessSet() error is nil, want empty set rejection")
	}
}

func TestDeleteExternalAccessSetRemovesOnlyRequestedSet(t *testing.T) {
	initial := &egressv1.EgressPolicy{
		PolicyId: policyID,
		AccessSets: []*egressv1.ExternalAccessSet{
			testTLSAccessSet("support.external-rule-set.bootstrap", "bootstrap.raw", "raw.githubusercontent.com", "code-code/platform-support-service"),
			testHTTPSAccessSet("support.external-rule-set.l7-smoke", "smoke.httpbin", "httpbin.org", "code-code/l7-smoke-client"),
		},
	}
	service := testService(t, policyConfigMap(t, initial))

	result, err := service.DeleteExternalAccessSet(context.Background(), policyID, "support.external-rule-set.l7-smoke")
	if err != nil {
		t.Fatalf("DeleteExternalAccessSet() error = %v", err)
	}
	if got, want := result.RemovedExternalRule, int32(1); got != want {
		t.Fatalf("RemovedExternalRule = %d, want %d", got, want)
	}
	if got, want := result.RemovedServiceRule, int32(1); got != want {
		t.Fatalf("RemovedServiceRule = %d, want %d", got, want)
	}
	if got, want := result.RemovedHTTPRoute, int32(1); got != want {
		t.Fatalf("RemovedHTTPRoute = %d, want %d", got, want)
	}

	stored := loadStoredPolicy(t, service.client)
	if got, want := len(stored.GetAccessSets()), 1; got != want {
		t.Fatalf("stored access sets = %d, want %d", got, want)
	}
	if got, want := stored.GetAccessSets()[0].GetAccessSetId(), "support.external-rule-set.bootstrap"; got != want {
		t.Fatalf("remaining access set = %q, want %q", got, want)
	}
	if got, want := len(result.Item.GetPolicy().GetAccessSets()), 1; got != want {
		t.Fatalf("view access sets = %d, want %d", got, want)
	}
}

func TestDeleteExternalAccessSetIsIdempotentForMissingSet(t *testing.T) {
	initial := &egressv1.EgressPolicy{
		PolicyId: policyID,
		AccessSets: []*egressv1.ExternalAccessSet{
			testTLSAccessSet("support.external-rule-set.bootstrap", "bootstrap.raw", "raw.githubusercontent.com", "code-code/platform-support-service"),
		},
	}
	service := testService(t, policyConfigMap(t, initial))

	result, err := service.DeleteExternalAccessSet(context.Background(), policyID, "missing")
	if err != nil {
		t.Fatalf("DeleteExternalAccessSet() error = %v", err)
	}
	if result.RemovedExternalRule != 0 || result.RemovedServiceRule != 0 || result.RemovedHTTPRoute != 0 {
		t.Fatalf("removed counts = external:%d service:%d http:%d, want all zero", result.RemovedExternalRule, result.RemovedServiceRule, result.RemovedHTTPRoute)
	}
	stored := loadStoredPolicy(t, service.client)
	if got, want := len(stored.GetAccessSets()), 1; got != want {
		t.Fatalf("stored access sets = %d, want %d", got, want)
	}
}

func testService(t *testing.T, objects ...runtime.Object) *Service {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	service, err := NewService(ServiceConfig{
		Client:    client,
		Reader:    client,
		Namespace: "code-code-net",
		EgressRuntime: EgressRuntimeConfig{
			Namespace: "code-code-net",
		},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func policyConfigMap(t *testing.T, policy *egressv1.EgressPolicy) *corev1.ConfigMap {
	t.Helper()
	normalized, err := normalizePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := policyJSON.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "code-code-net",
			Name:      policyConfigMapName,
		},
		Data: map[string]string{policyConfigKey: string(payload)},
	}
}

func loadStoredPolicy(t *testing.T, client ctrlclient.Client) *egressv1.EgressPolicy {
	t.Helper()
	config := &corev1.ConfigMap{}
	if err := client.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "code-code-net", Name: policyConfigMapName}, config); err != nil {
		t.Fatalf("get policy config: %v", err)
	}
	policy := &egressv1.EgressPolicy{}
	if err := policyJSONRead.Unmarshal([]byte(config.Data[policyConfigKey]), policy); err != nil {
		t.Fatalf("parse policy config: %v", err)
	}
	return policy
}

func testTLSAccessSet(accessSetID, destinationID, host, serviceAccount string) *egressv1.ExternalAccessSet {
	return &egressv1.ExternalAccessSet{
		AccessSetId:  accessSetID,
		DisplayName:  accessSetID,
		OwnerService: "platform-support-service",
		PolicyId:     policyID,
		ExternalRules: []*egressv1.ExternalRule{{
			ExternalRuleId: accessSetID + ".rule",
			DestinationId:  destinationID,
			DisplayName:    host,
			HostMatch:      exactHost(host),
			Port:           443,
			Protocol:       egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
			Resolution:     egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
		}},
		ServiceRules: []*egressv1.ServiceRule{{
			ServiceRuleId:         destinationID + ".services",
			DestinationId:         destinationID,
			SourceServiceAccounts: []string{serviceAccount},
		}},
	}
}

func testHTTPSAccessSet(accessSetID, destinationID, host, serviceAccount string) *egressv1.ExternalAccessSet {
	accessSet := testTLSAccessSet(accessSetID, destinationID, host, serviceAccount)
	accessSet.ExternalRules[0].Protocol = egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS
	accessSet.HttpRoutes = []*egressv1.HttpEgressRoute{{
		RouteId:       accessSetID + ".route",
		DisplayName:   "L7 smoke",
		DestinationId: destinationID,
		Matches: []*egressv1.HttpRouteMatch{{
			PathPrefixes: []string{"/headers"},
			Methods:      []string{"GET"},
		}},
	}}
	return accessSet
}
