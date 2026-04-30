package authservice

import "code-code.internal/platform-k8s/internal/platform/grpcerrors"

// grpcError maps one Go error to one gRPC status error.
func grpcError(err error) error {
	return grpcerrors.MapError(err)
}
