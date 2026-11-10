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
	// sessions by user ID, then repository key; seals and changes by
	// session ID, then command or change ID
	sessions map[int64]map[string]Session
	seals    map[string]map[string]Seal
	changes  map[string]map[string]Change
}

// NewMemory returns an empty in-memory Store.
func NewMemory() *Memory {
	return &Memory{
		agents:   map[string]AgentState{},
		keys:     map[string]KeyRecord{},
		replays:  map[string]time.Time{},
		commands: map[string]map[string]CommandRecord{},
		escrow:   map[string]protocol.EscrowRecord{},
		sessions: map[int64]map[string]Session{},
		seals:    map[string]map[string]Seal{},
		changes:  map[string]map[string]Change{},
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

func (m *Memory) Command(_ context.Context, agentID, id string) (CommandRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.commands[agentID][id]
	return c, ok, nil
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
	c.Secret = ""
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

func (m *Memory) CreateSession(_ context.Context, s Session, maxSessions int, now time.Time) (Session, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := RepoKey(s.Owner, s.Repo)
	live := 0
	for k, existing := range m.sessions[s.UserID] {
		if !existing.Live(now) {
			continue
		}
		if k == key {
			return existing, false, nil
		}
		live++
	}
	if live >= maxSessions {
		return Session{}, false, ErrTooManySessions
	}
	if m.sessions[s.UserID] == nil {
		m.sessions[s.UserID] = map[string]Session{}
	}
	m.sessions[s.UserID][key] = s
	return s, true, nil
}

func (m *Memory) Session(_ context.Context, userID int64, repoKey string, now time.Time) (Session, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[userID][repoKey]
	if !ok || !s.Live(now) {
		return Session{}, false, nil
	}
	return s, true, nil
}

func (m *Memory) Sessions(_ context.Context, userID int64, now time.Time) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Session{}
	for _, s := range m.sessions[userID] {
		if s.Live(now) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return RepoKey(out[i].Owner, out[i].Repo) < RepoKey(out[j].Owner, out[j].Repo) })
	return out, nil
}

func (m *Memory) TouchSession(_ context.Context, userID int64, repoKey, id string, expires, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[userID][repoKey]
	if !ok || s.ID != id || !s.Live(now) {
		return false, nil
	}
	if s.Locked(now) {
		return false, ErrSessionBusy
	}
	s.UsedAt, s.ExpiresAt = now, expires
	m.sessions[userID][repoKey] = s
	return true, nil
}

func (m *Memory) LockSession(_ context.Context, userID int64, repoKey, id string, until, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[userID][repoKey]
	if !ok || s.ID != id || !s.Live(now) || s.Locked(now) {
		return false, nil
	}
	s.SubmitDeadline = until.UnixMilli()
	m.sessions[userID][repoKey] = s
	return true, nil
}

func (m *Memory) UnlockSession(_ context.Context, userID int64, repoKey, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[userID][repoKey]; ok && s.ID == id {
		s.SubmitDeadline = 0
		m.sessions[userID][repoKey] = s
	}
	return nil
}

func (m *Memory) DeleteSession(_ context.Context, userID int64, repoKey, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[userID][repoKey]
	if !ok || s.ID != id {
		return false, nil
	}
	delete(m.sessions[userID], repoKey)
	return true, nil
}

func (m *Memory) DiscardSession(_ context.Context, userID int64, repoKey, id string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[userID][repoKey]
	switch {
	case !ok || s.ID != id || !s.Live(now):
		return false, nil
	case s.Locked(now):
		return false, ErrSessionBusy
	}
	delete(m.sessions[userID], repoKey)
	return true, nil
}

func (m *Memory) PutSeal(_ context.Context, s Seal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seals[s.SessionID] == nil {
		m.seals[s.SessionID] = map[string]Seal{}
	}
	m.seals[s.SessionID][s.CommandID] = s
	return nil
}

func (m *Memory) Seal(_ context.Context, sessionID, commandID string) (Seal, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.seals[sessionID][commandID]
	return s, ok, nil
}

func (m *Memory) PutChange(_ context.Context, c Change) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, ok := m.changes[c.SessionID][c.ID]; ok && prev.CommandID > c.CommandID {
		return false, nil
	}
	if m.changes[c.SessionID] == nil {
		m.changes[c.SessionID] = map[string]Change{}
	}
	m.changes[c.SessionID][c.ID] = c
	return true, nil
}

func (m *Memory) Changes(_ context.Context, sessionID string, ciphertexts bool) ([]Change, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Change{}
	for _, c := range m.changes[sessionID] {
		if !ciphertexts {
			c.Ciphertexts = nil
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) RemoveChange(_ context.Context, userID int64, repoKey, sessionID, id string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[userID][repoKey]
	switch {
	case !ok || s.ID != sessionID || !s.Live(now):
		return false, nil
	case s.Locked(now):
		return false, ErrSessionBusy
	}
	if _, ok := m.changes[sessionID][id]; !ok {
		return false, nil
	}
	delete(m.changes[sessionID], id)
	return true, nil
}

func (m *Memory) PruneChange(_ context.Context, sessionID, id, commandID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.changes[sessionID][id]; !ok || c.CommandID != commandID {
		return false, nil
	}
	delete(m.changes[sessionID], id)
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
