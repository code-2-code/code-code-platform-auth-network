package credentials

import (
	"context"
	"strings"
	"sync"

	"code-code.internal/go-contract/domainerror"
)

type memoryCredentialMaterialStore struct {
	mu     sync.Mutex
	values map[string]map[string]string
}

func newMemoryCredentialMaterialStore(initial map[string]map[string]string) *memoryCredentialMaterialStore {
	store := &memoryCredentialMaterialStore{values: map[string]map[string]string{}}
	for credentialID, values := range initial {
		credentialID = strings.TrimSpace(credentialID)
		if credentialID == "" {
			continue
		}
		store.values[credentialID] = cloneMaterialValuesForTest(values)
	}
	return store
}

func (s *memoryCredentialMaterialStore) ReadValues(_ context.Context, credentialID string) (map[string]string, error) {
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return nil, domainerror.NewValidation("credentials: credential id is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneMaterialValuesForTest(s.values[credentialID]), nil
}

func (s *memoryCredentialMaterialStore) WriteValues(_ context.Context, credentialID string, values map[string]string) error {
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return domainerror.NewValidation("credentials: credential id is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[credentialID] = cloneMaterialValuesForTest(trimMaterialValueUpdates(values))
	return nil
}

func (s *memoryCredentialMaterialStore) MergeValues(_ context.Context, credentialID string, values map[string]string) error {
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return domainerror.NewValidation("credentials: credential id is empty")
	}
	updates := trimMaterialValueUpdates(values)
	if len(updates) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values[credentialID] == nil {
		s.values[credentialID] = map[string]string{}
	}
	for key, value := range updates {
		s.values[credentialID][key] = value
	}
	return nil
}

func (s *memoryCredentialMaterialStore) DeleteValues(_ context.Context, credentialID string) error {
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return domainerror.NewValidation("credentials: credential id is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, credentialID)
	return nil
}

func (s *memoryCredentialMaterialStore) valuesForTest(credentialID string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneMaterialValuesForTest(s.values[strings.TrimSpace(credentialID)])
}

func cloneMaterialValuesForTest(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
