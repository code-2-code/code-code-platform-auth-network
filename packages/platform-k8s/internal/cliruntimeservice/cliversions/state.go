package cliversions

import (
	"context"
	"time"
)

type State struct {
	Versions map[string]Snapshot `json:"versions"`
}

type Snapshot struct {
	Version   string    `json:"version"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

func newState() *State {
	return &State{Versions: map[string]Snapshot{}}
}

type Store interface {
	Load(context.Context) (*State, error)
	Save(context.Context, *State) error
}

func (s *State) clone() *State {
	if s == nil {
		return newState()
	}
	clone := newState()
	for cliID, snapshot := range s.Versions {
		clone.Versions[cliID] = snapshot
	}
	return clone
}
