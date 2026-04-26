package credential

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// DeviceAuthorizationStatus identifies one device authorization state.
type DeviceAuthorizationStatus string

const (
	DeviceAuthorizationStatusPending    DeviceAuthorizationStatus = "pending"
	DeviceAuthorizationStatusAuthorized DeviceAuthorizationStatus = "authorized"
	DeviceAuthorizationStatusDenied     DeviceAuthorizationStatus = "denied"
	DeviceAuthorizationStatusExpired    DeviceAuthorizationStatus = "expired"
)

// DeviceAuthorizationRequest describes one request to start a device authorization flow.
type DeviceAuthorizationRequest struct{}

// DeviceAuthorizationSession describes one pending device authorization flow.
type DeviceAuthorizationSession struct {
	SessionID           string
	AuthorizationURL    string
	UserCode            string
	PollIntervalSeconds int32
	ExpiresAt           time.Time
}

// DeviceAuthorizationResult describes one poll result for one device authorization flow.
type DeviceAuthorizationResult struct {
	Status              DeviceAuthorizationStatus
	Artifact            *OAuthArtifact
	PollIntervalSeconds int32
}

// DeviceAuthorizer starts and polls device authorization flows (RFC 8628).
type DeviceAuthorizer interface {
	// StartAuthorizationSession starts one device authorization flow.
	StartAuthorizationSession(ctx context.Context, request *DeviceAuthorizationRequest) (*DeviceAuthorizationSession, error)

	// PollAuthorizationSession polls one device authorization flow once.
	PollAuthorizationSession(ctx context.Context, sessionID string) (*DeviceAuthorizationResult, error)
}

// ValidateDeviceAuthorizationRequest validates one device authorization request.
func ValidateDeviceAuthorizationRequest(request *DeviceAuthorizationRequest) error {
	if request == nil {
		return fmt.Errorf("credential: device authorization request is nil")
	}
	return nil
}

// ValidateDeviceAuthorizationStatus validates one device authorization status.
func ValidateDeviceAuthorizationStatus(status DeviceAuthorizationStatus) error {
	switch status {
	case DeviceAuthorizationStatusPending,
		DeviceAuthorizationStatusAuthorized,
		DeviceAuthorizationStatusDenied,
		DeviceAuthorizationStatusExpired:
		return nil
	default:
		return fmt.Errorf("credential: unsupported device authorization status %q", status)
	}
}

// ValidateDeviceAuthorizationSession validates one device authorization session.
func ValidateDeviceAuthorizationSession(session *DeviceAuthorizationSession) error {
	if session == nil {
		return fmt.Errorf("credential: device authorization session is nil")
	}
	if strings.TrimSpace(session.SessionID) == "" {
		return fmt.Errorf("credential: device authorization session id is empty")
	}
	if strings.TrimSpace(session.AuthorizationURL) == "" {
		return fmt.Errorf("credential: device authorization url is empty")
	}
	if strings.TrimSpace(session.UserCode) == "" {
		return fmt.Errorf("credential: device authorization user code is empty")
	}
	if session.PollIntervalSeconds <= 0 {
		return fmt.Errorf("credential: device authorization poll interval is empty")
	}
	if session.ExpiresAt.IsZero() {
		return fmt.Errorf("credential: device authorization expiry is empty")
	}
	return nil
}

// ValidateDeviceAuthorizationResult validates one device authorization result.
func ValidateDeviceAuthorizationResult(result *DeviceAuthorizationResult) error {
	if result == nil {
		return fmt.Errorf("credential: device authorization result is nil")
	}
	if err := ValidateDeviceAuthorizationStatus(result.Status); err != nil {
		return err
	}
	if result.PollIntervalSeconds < 0 {
		return fmt.Errorf("credential: device authorization poll interval is invalid")
	}
	if result.Status == DeviceAuthorizationStatusAuthorized {
		if err := ValidateOAuthArtifact(result.Artifact); err != nil {
			return fmt.Errorf("credential: device authorization artifact is invalid: %w", err)
		}
	}
	return nil
}
