# code-code-platform-auth-network

Auth and network policy services split from the Code Code platform.

This repository owns:

- `packages/platform-k8s/internal/authservice`: credential material, OAuth sessions, credential refresh, and auth projection.
- `packages/platform-k8s/internal/egressservice`: egress policy resources and runtime observability policy.
- `packages/platform-k8s/internal/egressauth`: Envoy auth processor policy and request/response header behavior.
- `packages/platform-k8s/internal/sessioncookie`: session cookie parsing helpers.
- Runtime entrypoints for auth and egress services.

Contracts are consumed through the `code-code-contracts` submodule.

Useful checks:

```bash
git submodule update --init --recursive
cd packages/platform-k8s
go test ./internal/authservice/... ./internal/egressservice/... ./internal/egressauth/... ./internal/egressauthpolicy/... ./internal/sessioncookie/... ./cmd/platform-auth-service ./cmd/platform-egress-service
```
