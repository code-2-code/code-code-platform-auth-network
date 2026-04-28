package authservice

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func errOAuthSessionUnavailable() error {
	return fmt.Errorf("platformk8s/authservice: oauth session service is unavailable")
}

func timeToProto(value *time.Time) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	return timestamppb.New(value.UTC())
}
