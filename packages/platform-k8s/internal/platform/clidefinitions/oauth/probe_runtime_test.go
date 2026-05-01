package oauth

import (
	"context"
	"net/http"
	"testing"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
	"code-code.internal/platform-k8s/internal/cliruntimeservice/cliversions"
)

func TestApplyOAuthProbeClientIdentityHeaders(t *testing.T) {
	headers := ApplyOAuthProbeClientIdentityHeaders(http.Header{}, &supportv1.CLI{
		CliId: "antigravity",
		Oauth: &supportv1.OAuthSupport{
			ClientIdentity: &supportv1.OAuthClientIdentity{
				ObservabilityUserAgentTemplate: "antigravity/${client_version} darwin/arm64",
			},
		},
	}, "1.22.2")
	if got, want := headers.Get("User-Agent"), "antigravity/1.22.2 darwin/arm64"; got != want {
		t.Fatalf("user-agent = %q, want %q", got, want)
	}
}

func TestResolveOAuthDiscoveryDynamicValues(t *testing.T) {
	versionStore := staticVersionStore{state: &cliversions.State{
		Versions: map[string]cliversions.Snapshot{
			"codex": {Version: "1.2.3"},
		},
	}}

	values, err := ResolveOAuthDiscoveryDynamicValues(context.Background(), versionStore, "codex")
	if err != nil {
		t.Fatalf("ResolveOAuthDiscoveryDynamicValues() error = %v", err)
	}
	if got, want := values.ClientVersion, "1.2.3"; got != want {
		t.Fatalf("client_version = %q, want %q", got, want)
	}
}

type staticVersionStore struct {
	state *cliversions.State
}

func (s staticVersionStore) Load(context.Context) (*cliversions.State, error) {
	return s.state, nil
}

func (s staticVersionStore) Save(context.Context, *cliversions.State) error {
	return nil
}
