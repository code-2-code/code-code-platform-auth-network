package support

import (
	"context"
	"fmt"
	"slices"
	"strings"

	observabilityv1 "code-code.internal/go-contract/observability/v1"
	supportv1 "code-code.internal/go-contract/platform/support/v1"
	"google.golang.org/protobuf/proto"
)

// ManagementService provides read-only access to registered CLI
// capabilities.
type ManagementService struct {
}

func NewManagementService() (*ManagementService, error) {
	return &ManagementService{}, nil
}

func (s *ManagementService) List(ctx context.Context) ([]*supportv1.CLI, error) {
	if s == nil {
		return nil, fmt.Errorf("platformk8s: cli support service is nil")
	}
	_ = ctx
	return RegisteredCLIs()
}

func RegisteredCLIs() ([]*supportv1.CLI, error) {
	cliIDs := staticCLIYAMLIDs()
	slices.Sort(cliIDs)

	items := make([]*supportv1.CLI, 0, len(cliIDs))
	for _, cliID := range cliIDs {
		item, err := materializeRegisteredCLI(cliID)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	slices.SortFunc(items, func(left, right *supportv1.CLI) int {
		leftName := left.GetDisplayName()
		if leftName == "" {
			leftName = left.GetCliId()
		}
		rightName := right.GetDisplayName()
		if rightName == "" {
			rightName = right.GetCliId()
		}
		if leftName < rightName {
			return -1
		}
		if leftName > rightName {
			return 1
		}
		return 0
	})
	return items, nil
}

func (s *ManagementService) Get(ctx context.Context, cliID string) (*supportv1.CLI, error) {
	if s == nil {
		return nil, fmt.Errorf("platformk8s: cli support service is nil")
	}
	_ = ctx
	return RegisteredCLI(cliID)
}

func RegisteredCLI(cliID string) (*supportv1.CLI, error) {
	return materializeRegisteredCLI(cliID)
}

func materializeRegisteredCLI(cliID string) (*supportv1.CLI, error) {
	cliID = strings.TrimSpace(cliID)
	if item, ok, err := materializeRegisteredCLIYAML(cliID); err != nil {
		return nil, err
	} else if ok {
		return finalizeRegisteredCLI(cliID, item)
	}
	return nil, fmt.Errorf("platformk8s: cli support %q not found", cliID)
}

func finalizeRegisteredCLI(cliID string, item *supportv1.CLI) (*supportv1.CLI, error) {
	next := proto.Clone(item).(*supportv1.CLI)
	if next.CliId == "" {
		next.CliId = cliID
	}
	normalizeOAuthProviderBinding(next)
	if err := ValidateRuntimeCapabilities(next); err != nil {
		return nil, err
	}
	if err := ValidateAuthMaterializations(next); err != nil {
		return nil, err
	}
	if err := ValidateCredentialSubjectSummaryFields(next); err != nil {
		return nil, err
	}
	if err := ValidateOAuthClientIdentity(next); err != nil {
		return nil, err
	}
	if next.GetOauth() != nil && next.GetOauth().GetObservability() != nil {
		if err := observabilityv1.ValidateCapability(next.GetOauth().GetObservability()); err != nil {
			return nil, fmt.Errorf("platformk8s: invalid cli oauth observability for %q: %w", next.GetCliId(), err)
		}
	}
	return next, nil
}

func firstActiveQueryCollectorID(capability *observabilityv1.ObservabilityCapability) string {
	for _, profile := range capability.GetProfiles() {
		activeQuery := profile.GetActiveQuery()
		if activeQuery == nil {
			continue
		}
		if collectorID := strings.TrimSpace(activeQuery.GetCollectorId()); collectorID != "" {
			return collectorID
		}
	}
	return ""
}
