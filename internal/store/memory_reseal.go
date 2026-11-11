package store

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// resealMemory is what the in-memory store keeps for resealing. Memory's
// mutex guards it.
type resealMemory struct {
	// file reseals by session ID, then reseal ID
	fileReseals map[string]map[string]FileReseal
	// pull requests by sort key (pullSortKey)
	pulls map[string]ResealPullRequest
	runs  runMemory
}

func (m *Memory) PutFileReseal(_ context.Context, r FileReseal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reseal.fileReseals == nil {
		m.reseal.fileReseals = map[string]map[string]FileReseal{}
	}
	if m.reseal.fileReseals[r.SessionID] == nil {
		m.reseal.fileReseals[r.SessionID] = map[string]FileReseal{}
	}
	if _, ok := m.reseal.fileReseals[r.SessionID][r.ID]; ok {
		return fmt.Errorf("failed to store reseal %s: it exists", r.ID)
	}
	r.Outcomes = maps.Clone(r.Outcomes)
	if r.Outcomes == nil {
		r.Outcomes = map[string]ResealOutcome{}
	}
	m.reseal.fileReseals[r.SessionID][r.ID] = r
	return nil
}

func (m *Memory) FileReseal(_ context.Context, sessionID, id string) (FileReseal, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reseal.fileReseals[sessionID][id]
	r.Outcomes = maps.Clone(r.Outcomes)
	return r, ok, nil
}

func (m *Memory) RecordResealOutcome(_ context.Context, sessionID, id, commandID string, o ResealOutcome) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reseal.fileReseals[sessionID][id]
	if !ok {
		return false, nil
	}
	if _, done := r.Outcomes[commandID]; done {
		return false, nil
	}
	r.Outcomes = maps.Clone(r.Outcomes)
	r.Outcomes[commandID] = o
	m.reseal.fileReseals[sessionID][id] = r
	return true, nil
}

func (m *Memory) PutResealPullRequest(_ context.Context, p ResealPullRequest) error {
	if err := p.check(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reseal.pulls == nil {
		m.reseal.pulls = map[string]ResealPullRequest{}
	}
	p.FromKeys = slices.Clone(p.FromKeys)
	m.reseal.pulls[pullSortKey(p.State == PullOpen, p.RepoKey(), p.Number)] = p
	return nil
}

func (m *Memory) ResealPullRequests(_ context.Context, open bool, repoKey string) ([]ResealPullRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := pullDonePrefix
	if open {
		prefix = pullOpenPrefix
	}
	if repoKey != "" {
		prefix += repoKey + "#"
	}
	var keys []string
	for k, p := range m.reseal.pulls {
		// as the table's TTL would, once it has run
		if strings.HasPrefix(k, prefix) && (p.State == PullOpen || m.now().Before(p.endedAt().Add(ResealRetention))) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := []ResealPullRequest{}
	for _, k := range keys {
		out = append(out, m.reseal.pulls[k])
	}
	return out, nil
}

func (m *Memory) UpdateResealPullRequest(_ context.Context, p ResealPullRequest) (bool, error) {
	if err := p.check(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	open := pullSortKey(true, p.RepoKey(), p.Number)
	if _, ok := m.reseal.pulls[open]; !ok {
		return false, nil
	}
	if p.State != PullOpen {
		delete(m.reseal.pulls, open)
	}
	m.reseal.pulls[pullSortKey(p.State == PullOpen, p.RepoKey(), p.Number)] = p
	return true, nil
}
