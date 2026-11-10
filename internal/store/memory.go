package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// Memory is an in-memory Store for tests.
type Memory struct {
	mu      sync.Mutex
	agents  map[string]AgentState
	keys    map[string]KeyRecord
	replays map[string]time.Time
	// commands by agent ID, then command ID
	commands map[string]map[string]CommandRecord
	escrow   map[string]protocol.EscrowRecord
}

// NewMemory returns an empty in-memory Store.
func NewMemory() *Memory {
	return &Memory{
		agents:   map[string]AgentState{},
		keys:     map[string]KeyRecord{},
		replays:  map[string]time.Time{},
		commands: map[string]map[string]CommandRecord{},
		escrow:   map[string]protocol.EscrowRecord{},
	}
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

func (m *Memory) PutCommand(_ context.Context, c CommandRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.commands[c.AgentID] == nil {
		m.commands[c.AgentID] = map[string]CommandRecord{}
	}
	m.commands[c.AgentID][c.ID] = c
	return nil
}

func (m *Memory) Commands(_ context.Context, agentID string) ([]CommandRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CommandRecord, 0, len(m.commands[agentID]))
	for _, c := range m.commands[agentID] {
		out = append(out, c)
	}
	// IDs are ULIDs, so ID order is creation order
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) LeaseCommand(_ context.Context, agentID, id string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.commands[agentID][id]
	if !ok || c.Status != CommandQueued || !now.Before(c.ExpiresAt) {
		return false, nil
	}
	c.Status = CommandLeased
	c.LeasedAt = &now
	m.commands[agentID][id] = c
	return true, nil
}

func (m *Memory) FinishCommand(_ context.Context, agentID, id, status, result, errMsg string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.commands[agentID][id]
	if !ok || c.Status != CommandLeased || !now.Before(c.ExpiresAt) {
		return false, nil
	}
	c.Status, c.Result, c.Error, c.FinishedAt = status, result, errMsg, &now
	m.commands[agentID][id] = c
	return true, nil
}

func (m *Memory) PutEscrowIfAbsent(_ context.Context, rec protocol.EscrowRecord) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.escrow[rec.Fingerprint]; ok {
		return false, nil
	}
	m.escrow[rec.Fingerprint] = rec
	return true, nil
}

func (m *Memory) Escrow(_ context.Context, fingerprint string) (protocol.EscrowRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.escrow[fingerprint]
	return rec, ok, nil
}

func (m *Memory) Escrowed(_ context.Context, fingerprints []string) (map[string]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for _, fp := range fingerprints {
		if _, ok := m.escrow[fp]; ok {
			out[fp] = true
		}
	}
	return out, nil
}

// Key returns a recorded key, for tests.
func (m *Memory) Key(fingerprint string) (KeyRecord, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[fingerprint]
	return k, ok
}

var _ Store = (*Memory)(nil)
