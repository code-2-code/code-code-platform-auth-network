package cliversions

import (
	"context"
	"fmt"
	"strings"
)

func Resolve(ctx context.Context, store Store, cliID string) (string, error) {
	if store == nil {
		return "", fmt.Errorf("platformk8s/cliversions: store is nil")
	}
	trimmedCLIID := strings.TrimSpace(cliID)
	if trimmedCLIID == "" {
		return "", fmt.Errorf("platformk8s/cliversions: cli id is empty")
	}
	state, err := store.Load(ctx)
	if err != nil {
		return "", err
	}
	if snapshot, ok := state.Versions[trimmedCLIID]; ok && strings.TrimSpace(snapshot.Version) != "" {
		return strings.TrimSpace(snapshot.Version), nil
	}
	return "", nil
}
