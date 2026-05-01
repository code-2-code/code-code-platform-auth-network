package support

import (
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	providerv1 "code-code.internal/go-contract/provider/v1"
	"google.golang.org/protobuf/proto"
)

func MaterializeEndpoints(surface *supportv1.Surface) []*providerv1.ProviderEndpoint {
	endpoints := SurfaceEndpoints(surface)
	out := make([]*providerv1.ProviderEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint == nil {
			continue
		}
		out = append(out, proto.Clone(endpoint).(*providerv1.ProviderEndpoint))
	}
	return out
}
