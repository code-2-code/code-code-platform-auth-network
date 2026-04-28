package egresspolicies

import (
	"testing"

	egressv1 "code-code.internal/go-contract/egress/v1"
)

func TestDesiredStateMergesDestinationServiceAccounts(t *testing.T) {
	policy, err := normalizePolicy(&egressv1.EgressPolicy{
		PolicyId: "code-code-egress",
		AccessSets: []*egressv1.ExternalAccessSet{
			{
				AccessSetId:  "support",
				OwnerService: "platform-support-service",
				ExternalRules: []*egressv1.ExternalRule{{
					ExternalRuleId: "github-models",
					DestinationId:  "models.github",
					HostMatch:      exactHost("models.github.ai"),
					Port:           443,
					Protocol:       egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
					Resolution:     egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
				}},
				ServiceRules: []*egressv1.ServiceRule{{
					ServiceRuleId:         "github-models.services",
					DestinationId:         "models.github",
					SourceServiceAccounts: []string{"code-code/platform-model-service"},
				}},
			},
			{
				AccessSetId: "extra",
				ExternalRules: []*egressv1.ExternalRule{{
					ExternalRuleId: "github-models",
					DestinationId:  "models.github",
					HostMatch:      exactHost("models.github.ai"),
					Port:           443,
					Protocol:       egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
					Resolution:     egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
				}},
				ServiceRules: []*egressv1.ServiceRule{{
					ServiceRuleId:         "github-models.services",
					DestinationId:         "models.github",
					SourceServiceAccounts: []string{"code-code/platform-support-service"},
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("normalizePolicy() error = %v", err)
	}
	desired, err := desiredStateFromPolicy(policy)
	if err != nil {
		t.Fatalf("desiredStateFromPolicy() error = %v", err)
	}
	if got, want := len(desired.destinations), 1; got != want {
		t.Fatalf("destinations = %d, want %d", got, want)
	}
	accounts := desired.destinations[0].serviceAccounts
	if got, want := len(accounts), 2; got != want {
		t.Fatalf("serviceAccounts = %v, want %d accounts", accounts, want)
	}
}

func TestDesiredStateRejectsConflictingDestinationDeclarations(t *testing.T) {
	policy, err := normalizePolicy(&egressv1.EgressPolicy{
		PolicyId: "code-code-egress",
		AccessSets: []*egressv1.ExternalAccessSet{
			{
				AccessSetId: "a",
				ExternalRules: []*egressv1.ExternalRule{{
					ExternalRuleId: "a",
					DestinationId:  "shared",
					HostMatch:      exactHost("a.example.com"),
					Port:           443,
					Protocol:       egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
					Resolution:     egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
				}},
			},
			{
				AccessSetId: "b",
				ExternalRules: []*egressv1.ExternalRule{{
					ExternalRuleId: "b",
					DestinationId:  "shared",
					HostMatch:      exactHost("b.example.com"),
					Port:           443,
					Protocol:       egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
					Resolution:     egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("normalizePolicy() error = %v", err)
	}
	if _, err := desiredStateFromPolicy(policy); err == nil {
		t.Fatal("desiredStateFromPolicy() error is nil, want conflict")
	}
}

func TestDesiredStateProjectsAddressCIDR(t *testing.T) {
	policy, err := normalizePolicy(&egressv1.EgressPolicy{
		PolicyId: "code-code-egress",
		AccessSets: []*egressv1.ExternalAccessSet{{
			AccessSetId:  "network.preset-proxy",
			OwnerService: "platform-egress-service",
			ExternalRules: []*egressv1.ExternalRule{{
				ExternalRuleId: "preset-proxy",
				DestinationId:  "preset-proxy",
				HostMatch:      exactHost("preset-proxy.local"),
				AddressCidr:    "192.0.2.3/32",
				Port:           10809,
				Protocol:       egressv1.EgressProtocol_EGRESS_PROTOCOL_TCP,
				Resolution:     egressv1.EgressResolution_EGRESS_RESOLUTION_NONE,
			}},
			ServiceRules: []*egressv1.ServiceRule{{
				ServiceRuleId:         "preset-proxy.services",
				DestinationId:         "preset-proxy",
				SourceServiceAccounts: []string{"code-code/platform-support-service"},
			}},
		}},
	})
	if err != nil {
		t.Fatalf("normalizePolicy() error = %v", err)
	}
	desired, err := desiredStateFromPolicy(policy)
	if err != nil {
		t.Fatalf("desiredStateFromPolicy() error = %v", err)
	}
	if got, want := len(desired.destinations), 1; got != want {
		t.Fatalf("destinations = %d, want %d", got, want)
	}
	destination := desired.destinations[0]
	if got, want := destination.addressCidr, "192.0.2.3/32"; got != want {
		t.Fatalf("addressCidr = %q, want %q", got, want)
	}
	if got, want := destination.serviceAccounts, []string{"code-code/platform-support-service"}; !equalStringSlices(got, want) {
		t.Fatalf("service accounts = %v, want %v", got, want)
	}
}

func TestNormalizePolicyRejectsWildcardDestination(t *testing.T) {
	_, err := normalizePolicy(&egressv1.EgressPolicy{
		PolicyId: "code-code-egress",
		AccessSets: []*egressv1.ExternalAccessSet{{
			AccessSetId: "wildcard",
			ExternalRules: []*egressv1.ExternalRule{{
				ExternalRuleId: "aws",
				DestinationId:  "aws",
				HostMatch:      wildcardHost("*.amazonaws.com"),
				Port:           443,
				Protocol:       egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
				Resolution:     egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
			}},
		}},
	})
	if err == nil {
		t.Fatal("normalizePolicy() error is nil, want wildcard rejection")
	}
}

func TestDesiredStateAcceptsHTTPSDestinationForL7Route(t *testing.T) {
	policy, err := normalizePolicy(&egressv1.EgressPolicy{
		PolicyId: "code-code-egress",
		AccessSets: []*egressv1.ExternalAccessSet{{
			AccessSetId:  "support",
			OwnerService: "platform-support-service",
			ExternalRules: []*egressv1.ExternalRule{{
				ExternalRuleId: "openai",
				DestinationId:  "openai.api",
				HostMatch:      exactHost("api.openai.com"),
				Port:           443,
				Protocol:       egressv1.EgressProtocol_EGRESS_PROTOCOL_HTTPS,
				Resolution:     egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
			}},
			HttpRoutes: []*egressv1.HttpEgressRoute{{
				RouteId:       "openai-runtime-http",
				DestinationId: "openai.api",
				Matches: []*egressv1.HttpRouteMatch{{
					PathPrefixes: []string{"/v1/responses"},
					Methods:      []string{"POST"},
				}},
			}},
		}},
	})
	if err != nil {
		t.Fatalf("normalizePolicy() error = %v", err)
	}
	desired, err := desiredStateFromPolicy(policy)
	if err != nil {
		t.Fatalf("desiredStateFromPolicy() error = %v", err)
	}
	if got, want := len(desired.httpRoutes), 1; got != want {
		t.Fatalf("http routes = %d, want %d", got, want)
	}
}

func TestDesiredStateRejectsTLSDestinationForL7Route(t *testing.T) {
	policy, err := normalizePolicy(&egressv1.EgressPolicy{
		PolicyId: "code-code-egress",
		AccessSets: []*egressv1.ExternalAccessSet{{
			AccessSetId:  "support",
			OwnerService: "platform-support-service",
			ExternalRules: []*egressv1.ExternalRule{{
				ExternalRuleId: "openai",
				DestinationId:  "openai.api",
				HostMatch:      exactHost("api.openai.com"),
				Port:           443,
				Protocol:       egressv1.EgressProtocol_EGRESS_PROTOCOL_TLS,
				Resolution:     egressv1.EgressResolution_EGRESS_RESOLUTION_DNS,
			}},
			HttpRoutes: []*egressv1.HttpEgressRoute{{
				RouteId:       "openai-runtime-http",
				DestinationId: "openai.api",
			}},
		}},
	})
	if err != nil {
		t.Fatalf("normalizePolicy() error = %v", err)
	}
	if _, err := desiredStateFromPolicy(policy); err == nil {
		t.Fatal("desiredStateFromPolicy() error is nil, want TLS passthrough rejection")
	}
}

func exactHost(host string) *egressv1.HostMatch {
	return &egressv1.HostMatch{Kind: &egressv1.HostMatch_HostExact{HostExact: host}}
}

func wildcardHost(host string) *egressv1.HostMatch {
	return &egressv1.HostMatch{Kind: &egressv1.HostMatch_HostWildcard{HostWildcard: host}}
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
