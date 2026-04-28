package authservice

import (
	"errors"

	"code-code.internal/go-contract/domainerror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// grpcError maps one Go error to one gRPC status error.
func grpcError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	var notFound *domainerror.NotFoundError
	if errors.As(err, &notFound) {
		return status.Error(codes.NotFound, notFound.Error())
	}
	var alreadyExists *domainerror.AlreadyExistsError
	if errors.As(err, &alreadyExists) {
		return status.Error(codes.AlreadyExists, alreadyExists.Error())
	}
	var validation *domainerror.ValidationError
	if errors.As(err, &validation) {
		return status.Error(codes.InvalidArgument, validation.Error())
	}
	var refConflict *domainerror.ReferenceConflictError
	if errors.As(err, &refConflict) {
		return status.Error(codes.FailedPrecondition, refConflict.Error())
	}
	if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
		return status.Error(codes.AlreadyExists, err.Error())
	}
	if apierrors.IsNotFound(err) {
		return status.Error(codes.NotFound, err.Error())
	}
	if apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if apierrors.IsForbidden(err) {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	if apierrors.IsUnauthorized(err) {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	if apierrors.IsTooManyRequests(err) {
		return status.Error(codes.ResourceExhausted, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}
