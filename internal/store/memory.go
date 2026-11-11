package store

import (
	"context"
	"maps"
	"slices"
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
	// escrow holds each key's escrowed copies, the primary record first;
	// escrowExpires the purge time of a deleted key's copies
	escrow        map[string][]protocol.EscrowRecord
	escrowExpires map[string]time.Time
	revoked       map[string]RevokedKey
	reinstated    map[string]ReinstatedKey
	usage         map[string]KeyUsage
	// sessions by user ID, then repository key; seals and changes by
	// session ID, then command or change ID
	sessions map[int64]map[string]Session
	seals    map[string]map[string]Seal
	changes  map[string]map[string]Change
	// reserved holds the places seals hold among a session's changes, by
	// session ID, then change ID
	reserved map[string]map[string]int64
	// requests counts requests by rate limit window
	requests map[rateWindow]int
}

type rateWindow struct {
	key string
	end int64
}

// NewMemory returns an empty in-memory Store.
func NewMemory() *Memory {
	return &Memory{
		agents:   map[string]AgentState{},
		keys:     map[string]KeyRecord{},
		replays:  map[string]time.Time{},
		commands: map[string]map[string]CommandRecord{},
		escrow:   map[string][]protocol.EscrowRecord{},
		revoked:  map[string]RevokedKey{},
		usage:    map[string]KeyUsage{},
		sessions: map[int64]map[string]Session{},
		seals:    map[string]map[string]Seal{},
		changes:  map[string]map[string]Change{},
		reserved: map[string]map[string]int64{},
		requests: map[rateWindow]int{},

		escrowExpires: map[string]time.Time{},
		reinstated:    map[string]ReinstatedKey{},
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

func (m *Memory) GetKey(_ context.Context, fingerprint string) (KeyRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[fingerprint]
	return k, ok, nil
}

func (m *Memory) SetKeyStatus(_ context.Context, k KeyRecord) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[k.Fingerprint]
	switch {
	case !ok:
		return false, nil
	case rec.Status == KeyDeleted:
		return false, ErrKeyChanged
	}
	rec.Status, rec.StatusBy, rec.StatusAt = k.Status, k.StatusBy, k.StatusAt
	m.keys[k.Fingerprint] = rec
	delete(m.reinstated, k.Fingerprint)
	if k.Status == KeyRevoked {
		m.revoked[k.Fingerprint] = revokedKey(k)
	} else {
		delete(m.revoked, k.Fingerprint)
	}
	return true, nil
}

func (m *Memory) DeleteKey(_ context.Context, k KeyRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[k.Fingerprint]
	r, listed := m.revoked[k.Fingerprint]
	if !ok || rec.Status != KeyRevoked || !listed {
		return ErrKeyChanged
	}
	rec.Status, rec.StatusBy, rec.StatusAt, rec.PurgeAt = KeyDeleted, k.StatusBy, k.StatusAt, k.PurgeAt
	m.keys[k.Fingerprint] = rec
	r.Status, r.DeletedBy, r.DeletedAt, r.PurgeAt = KeyDeleted, k.StatusBy, k.StatusAt, k.PurgeAt
	m.revoked[k.Fingerprint] = r
	m.escrowExpires[k.Fingerprint] = *k.PurgeAt
	return nil
}

func (m *Memory) ReinstateDeletedKey(_ context.Context, k KeyRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[k.Fingerprint]
	if !ok || rec.Status != KeyDeleted {
		return ErrKeyChanged
	}
	rec.Status, rec.StatusBy, rec.StatusAt, rec.PurgeAt = KeyActive, k.StatusBy, k.StatusAt, nil
	m.keys[k.Fingerprint] = rec
	delete(m.revoked, k.Fingerprint)
	delete(m.escrowExpires, k.Fingerprint)
	m.reinstated[k.Fingerprint] = reinstatedKey(k)
	return nil
}

func (m *Memory) RevokedKeys(_ context.Context) (map[string]RevokedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.revoked), nil
}

func (m *Memory) KeyLists(_ context.Context) (KeyLists, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := KeyLists{Revoked: maps.Clone(m.revoked), Reinstated: map[string]ReinstatedKey{}}
	now := time.Now()
	for fp, r := range m.reinstated {
		if now.Before(r.At.Add(ReinstatedRestoreWindow)) {
			out.Reinstated[fp] = r
		}
	}
	return out, nil
}

func (m *Memory) PutKeyUsage(_ context.Context, u KeyUsage) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, ok := m.usage[u.AgentID]; ok && prev.ScannedAt.Equal(u.ScannedAt) {
		return false, nil
	}
	u.Namespaces, u.Keys = slices.Clone(u.Namespaces), maps.Clone(u.Keys)
	m.usage[u.AgentID] = u
	return true, nil
}

func (m *Memory) KeyUsages(_ context.Context, ids []string) (map[string]KeyUsage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]KeyUsage{}
	for _, id := range ids {
		if u, ok := m.usage[id]; ok {
			out[id] = u
		}
	}
	return out, nil
}

// escrowGone reports whether a key's escrowed copies are past their purge
// time, as the table's TTL would remove them. The caller holds m.mu.
func (m *Memory) escrowGone(fingerprint string) bool {
	at, ok := m.escrowExpires[fingerprint]
	return ok && !time.Now().Before(at)
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

func (m *Memory) CountRequest(_ context.Context, key string, n, limit int, windowEnd time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := rateWindow{key: key, end: windowEnd.Unix()}
	if m.requests[w] >= limit {
		return false, nil
	}
	m.requests[w] += n
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

func (m *Memory) CommandsSince(ctx context.Context, agentID string, since time.Time) ([]CommandRecord, error) {
	all, err := m.Commands(ctx, agentID)
	if err != nil {
		return nil, err
	}
	// the ID range DynamoDB reads
	floor := commandIDFloor(since)
	out := []CommandRecord{}
	for _, c := range all {
		if c.ID >= floor && c.ID <= commandIDCeiling {
			out = append(out, c)
		}
	}
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

func (m *Memory) PutEscrow(_ context.Context, rec protocol.EscrowRecord, maxCopies int) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	recs := m.escrow[rec.Fingerprint]
	if _, deleted := m.escrowExpires[rec.Fingerprint]; deleted && len(recs) > 0 {
		// a deleted key's copies expire together: none is added
		return false, false, nil
	}
	if len(recs) >= max(maxCopies, 1) || slices.ContainsFunc(recs, func(r protocol.EscrowRecord) bool { return r.UploadedBy == rec.UploadedBy }) {
		return false, false, nil
	}
	recs = append(recs, rec)
	// the primary record stays first; copies follow by uploader
	sort.SliceStable(recs[1:], func(i, j int) bool { return recs[1+i].UploadedBy < recs[1+j].UploadedBy })
	m.escrow[rec.Fingerprint] = recs
	return true, len(recs) == 1, nil
}

func (m *Memory) Escrow(_ context.Context, fingerprint string) ([]protocol.EscrowRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.escrowGone(fingerprint) {
		return []protocol.EscrowRecord{}, nil
	}
	return slices.Clone(m.escrow[fingerprint]), nil
}

func (m *Memory) EscrowUploaders(_ context.Context, fingerprints []string) (map[string][]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string][]string{}
	for _, fp := range fingerprints {
		if m.escrowGone(fp) {
			continue
		}
		for _, r := range m.escrow[fp] {
			if !slices.Contains(out[fp], r.UploadedBy) {
				out[fp] = append(out[fp], r.UploadedBy)
			}
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

func (m *Memory) ReserveChange(_ context.Context, sessionID, changeID, sealID string, existing []string, maxChanges int, until, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept, err := reserveChange(m.reserved[sessionID], changeID, sealID, existing, maxChanges, until, now)
	if err != nil {
		return err
	}
	m.reserved[sessionID] = kept
	return nil
}

func (m *Memory) ReleaseChange(_ context.Context, sessionID, changeID, sealID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept, _ := releaseChange(m.reserved[sessionID], changeID, sealID, now)
	m.reserved[sessionID] = kept
	return nil
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
