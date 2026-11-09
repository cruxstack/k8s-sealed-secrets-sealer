package store

import (
	"context"
	"sync"
	"time"
)

// Memory is an in-memory Store for tests.
type Memory struct {
	mu      sync.Mutex
	agents  map[string]AgentState
	keys    map[string]KeyRecord
	replays map[string]time.Time
}

// NewMemory returns an empty in-memory Store.
func NewMemory() *Memory {
	return &Memory{agents: map[string]AgentState{}, keys: map[string]KeyRecord{}, replays: map[string]time.Time{}}
}

func (m *Memory) PutAgentState(_ context.Context, s AgentState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.agents[s.AgentID] = s
	return nil
}

func (m *Memory) GetAgentStates(_ context.Context, ids []string) (map[string]AgentState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]AgentState{}
	for _, id := range ids {
		if s, ok := m.agents[id]; ok {
			out[id] = s
		}
	}
	return out, nil
}

func (m *Memory) PutKeyIfAbsent(_ context.Context, k KeyRecord) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[k.Fingerprint]; ok {
		return false, nil
	}
	m.keys[k.Fingerprint] = k
	return true, nil
}

func (m *Memory) PutReplayIfAbsent(_ context.Context, key string, expires time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, exp := range m.replays {
		if now.After(exp) {
			delete(m.replays, k)
		}
	}
	if _, ok := m.replays[key]; ok {
		return false, nil
	}
	m.replays[key] = expires
	return true, nil
}

// Key returns a recorded key, for tests.
func (m *Memory) Key(fingerprint string) (KeyRecord, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[fingerprint]
	return k, ok
}

var _ Store = (*Memory)(nil)
