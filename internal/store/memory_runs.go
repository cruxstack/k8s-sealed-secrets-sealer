package store

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"
)

// runMemory is what the in-memory store keeps of schedules and runs.
// Memory's mutex guards it.
type runMemory struct {
	schedules map[string]ResealSchedule
	runs      map[string]ResealRun
	// repositories, work and batches by run ID, then key
	repos   map[string]map[string]ResealRunRepo
	work    map[string]map[string]ResealWork
	batches map[string]map[string]ResealBatch
}

func (m *Memory) runs() *runMemory {
	r := &m.reseal.runs
	if r.schedules == nil {
		r.schedules = map[string]ResealSchedule{}
		r.runs = map[string]ResealRun{}
		r.repos = map[string]map[string]ResealRunRepo{}
		r.work = map[string]map[string]ResealWork{}
		r.batches = map[string]map[string]ResealBatch{}
	}
	return r
}

func cloneSchedule(s ResealSchedule) ResealSchedule {
	s.Repos, s.Orgs = slices.Clone(s.Repos), slices.Clone(s.Orgs)
	return s
}

func cloneRun(r ResealRun) ResealRun {
	r.Repos, r.Orgs, r.InFlight = slices.Clone(r.Repos), slices.Clone(r.Orgs), slices.Clone(r.InFlight)
	return r
}

func (m *Memory) CreateResealSchedule(_ context.Context, s ResealSchedule, maxSchedules int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs()
	if len(r.schedules) >= maxSchedules {
		return ErrTooManySchedules
	}
	if _, ok := r.schedules[s.ID]; ok {
		return fmt.Errorf("failed to store schedule %s: it exists", s.ID)
	}
	r.schedules[s.ID] = cloneSchedule(s)
	return nil
}

func (m *Memory) ResealSchedules(_ context.Context) ([]ResealSchedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ResealSchedule{}
	for _, s := range m.runs().schedules {
		out = append(out, cloneSchedule(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) ResealSchedule(_ context.Context, id string) (ResealSchedule, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.runs().schedules[id]
	return cloneSchedule(s), ok, nil
}

func (m *Memory) UpdateResealSchedule(_ context.Context, s ResealSchedule, setNext bool) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs()
	cur, ok := r.schedules[s.ID]
	if !ok {
		return false, nil
	}
	cur.Name, cur.Repos, cur.Orgs = s.Name, slices.Clone(s.Repos), slices.Clone(s.Orgs)
	cur.IntervalDays, cur.Enabled = s.IntervalDays, s.Enabled
	if setNext {
		cur.NextRunAt = s.NextRunAt
	}
	cur.UpdatedBy, cur.UpdatedAt = s.UpdatedBy, s.UpdatedAt
	r.schedules[s.ID] = cur
	return true, nil
}

func (m *Memory) DeleteResealSchedule(_ context.Context, id, by string, now time.Time) (ResealSchedule, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs()
	s, ok := r.schedules[id]
	if !ok {
		return ResealSchedule{}, false, nil
	}
	delete(r.schedules, id)
	if run, found := r.runs[s.ActiveRunID]; found && run.Active() {
		run.Status, run.FinishedAt, run.CancelledBy, run.LeaseUntil = RunCancelled, &now, by, 0
		r.runs[run.ID] = run
	}
	return s, true, nil
}

func (m *Memory) StartResealRun(_ context.Context, run ResealRun, expectNext, next *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs()
	s, ok := r.schedules[run.ScheduleID]
	switch {
	case ok && s.ActiveRunID != "":
		return ErrRunActive
	case !ok, expectNext != nil && (s.NextRunAt == nil || !s.NextRunAt.Equal(*expectNext)):
		return ErrScheduleChanged
	}
	if _, exists := r.runs[run.ID]; exists {
		return fmt.Errorf("failed to start run %s: it exists", run.ID)
	}
	s.ActiveRunID, s.LastRunID = run.ID, run.ID
	if expectNext != nil && next != nil {
		s.NextRunAt = next
	}
	r.schedules[s.ID] = s
	r.runs[run.ID] = cloneRun(run)
	return nil
}

func (m *Memory) ResealRun(_ context.Context, id string) (ResealRun, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs().runs[id]
	return cloneRun(run), ok, nil
}

func (m *Memory) ResealRuns(_ context.Context, scheduleID string, limit int) ([]ResealRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ResealRun{}
	for _, run := range m.runs().runs {
		gone := run.FinishedAt != nil && !m.now().Before(run.FinishedAt.Add(ResealRetention))
		if !gone && (scheduleID == "" || run.ScheduleID == scheduleID) {
			out = append(out, cloneRun(run))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) LeaseResealRun(_ context.Context, id string, until, now time.Time) (ResealRun, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs()
	run, ok := r.runs[id]
	if !ok || !run.Active() || run.LeaseUntil > now.UnixMilli() {
		return ResealRun{}, false, nil
	}
	run.LeaseUntil = until.UnixMilli()
	r.runs[id] = run
	return cloneRun(run), true, nil
}

func (m *Memory) SaveResealRun(_ context.Context, run ResealRun, held int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs()
	cur, ok := r.runs[run.ID]
	if !ok || !cur.Active() || cur.LeaseUntil != held {
		return false, nil
	}
	r.runs[run.ID] = cloneRun(run)
	if !run.Active() {
		m.endActiveRun(run.ScheduleID, run.ID)
	}
	return true, nil
}

func (m *Memory) CancelResealRun(_ context.Context, id, by string, now time.Time) (ResealRun, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs()
	run, ok := r.runs[id]
	if !ok || !run.Active() {
		return ResealRun{}, false, nil
	}
	run.Status, run.FinishedAt, run.CancelledBy, run.LeaseUntil = RunCancelled, &now, by, 0
	r.runs[id] = run
	m.endActiveRun(run.ScheduleID, id)
	return cloneRun(run), true, nil
}

// endActiveRun takes a run off its schedule's active run. The caller holds
// the mutex.
func (m *Memory) endActiveRun(scheduleID, runID string) {
	r := m.runs()
	if s, ok := r.schedules[scheduleID]; ok && s.ActiveRunID == runID {
		s.ActiveRunID = ""
		r.schedules[scheduleID] = s
	}
}

func (m *Memory) PutResealRunRepos(_ context.Context, repos []ResealRunRepo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs()
	for _, repo := range repos {
		if r.repos[repo.RunID] == nil {
			r.repos[repo.RunID] = map[string]ResealRunRepo{}
		}
		repo.Failures, repo.FromKeys = slices.Clone(repo.Failures), slices.Clone(repo.FromKeys)
		r.repos[repo.RunID][repo.Key] = repo
	}
	return nil
}

func (m *Memory) ResealRunRepo(_ context.Context, runID, key string) (ResealRunRepo, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	repo, ok := m.runs().repos[runID][key]
	return repo, ok, nil
}

func (m *Memory) ResealRunRepos(ctx context.Context, runID string) ([]ResealRunRepo, error) {
	return m.NextResealRunRepos(ctx, runID, "", 0)
}

func (m *Memory) NextResealRunRepos(_ context.Context, runID, after string, limit int) ([]ResealRunRepo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ResealRunRepo{}
	for key, repo := range m.runs().repos[runID] {
		if key > after {
			out = append(out, repo)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) PutResealWork(_ context.Context, w ResealWork) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs()
	if r.work[w.RunID] == nil {
		r.work[w.RunID] = map[string]ResealWork{}
	}
	w.Candidates, w.Files, w.Commands = slices.Clone(w.Candidates), slices.Clone(w.Files), slices.Clone(w.Commands)
	r.work[w.RunID][w.Key] = w
	return nil
}

func (m *Memory) ResealWork(_ context.Context, runID, key string) (ResealWork, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.runs().work[runID][key]
	w.Candidates, w.Files, w.Commands = slices.Clone(w.Candidates), slices.Clone(w.Files), slices.Clone(w.Commands)
	return w, ok, nil
}

func (m *Memory) PutResealBatch(_ context.Context, b ResealBatch) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs()
	if r.batches[b.RunID] == nil {
		r.batches[b.RunID] = map[string]ResealBatch{}
	}
	key := b.RepoKey + "#" + b.CommandID
	if _, ok := r.batches[b.RunID][key]; ok {
		return false, nil
	}
	b.Items = slices.Clone(b.Items)
	r.batches[b.RunID][key] = b
	return true, nil
}

func (m *Memory) ResealBatchesDone(_ context.Context, runID, repoKey string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, b := range m.runs().batches[runID] {
		if b.RepoKey == repoKey {
			out = append(out, b.CommandID)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (m *Memory) ResealBatch(_ context.Context, runID, repoKey, commandID string) (ResealBatch, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.runs().batches[runID][repoKey+"#"+commandID]
	b.Items = slices.Clone(b.Items)
	return b, ok, nil
}
