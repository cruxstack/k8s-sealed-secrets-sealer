package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/manifest"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/repos"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// A run reseals the values in a schedule's scope (docs/design.md,
// "Resealing"). Ticks drive it a bounded step at a time: one discovers its
// repositories, then each repository is started (its head read and its
// files listed), its files read and their values sent to agents, a few
// files a tick, and once every command answered or expired, one pull
// request is opened with every resealed value. A tick leases each run it
// advances, so overlapping ticks never advance one at once, and every step
// can be repeated: a tick that dies part way leaves work the next takes up.

// Run limits.
const (
	// maxSchedules bounds an env's schedules.
	maxSchedules = 50
	// maxRunRepos bounds the repositories one run covers.
	maxRunRepos = 500
	// maxRunFiles bounds the files with documents for the env a run reads
	// of one repository.
	maxRunFiles = 200
	// runLease is how long a tick holds a run it advances: longer than a
	// tick takes.
	runLease = 2 * time.Minute
	// maxReposInFlight bounds a run's repositories started and not done.
	maxReposInFlight = 5
	// maxAgentQueue bounds the commands in flight of an agent that runs
	// send it more.
	maxAgentQueue = 8
	// resultGrace is how long after a command expires its result may
	// still be recorded, by a request that began before.
	resultGrace = time.Minute
	// maxOpenAttempts bounds the tries to open a repository's pull request
	// that fail other than for the rate limit.
	maxOpenAttempts = 3
	// prRefreshPerTick bounds the pull requests a tick checks, and
	// prRefreshTicks is how many ticks apart each open one is checked:
	// about every 15 minutes at a tick a minute.
	prRefreshPerTick = 10
	prRefreshTicks   = 15
	// agentWait is how long after a run starts it waits for an agent that
	// can reseal, as one restarting comes back; after it, values that no
	// agent can take fail, and a later run tries them again.
	agentWait = 10 * time.Minute
	// skipRecheck is how old a check of an open pull request may be when
	// it skips a repository: older, it is checked again first.
	skipRecheck = time.Minute
	// tickMargin is the time a tick keeps to record what it did.
	tickMargin = 5 * time.Second
	// defaultTickTime bounds a tick with no deadline of its own.
	defaultTickTime = 50 * time.Second
	// DefaultTickInterval is how often ticks come unless told otherwise.
	DefaultTickInterval = time.Minute
)

// limitResealGitHub bounds the GitHub requests reseal ticks make in an env
// each minute, counted in the store so every instance shares it: runs must
// leave the App's hourly budget to people. One step that needs more, such
// as opening a pull request of many files, runs alone in a minute.
var limitResealGitHub = rateLimit{name: "reseal-github", max: 100, window: time.Minute}

// Reasons a repository is skipped or failed, as people read them.
const (
	reasonUnreachable = "The GitHub App cannot reach this repository."
	reasonArchived    = "The repository is archived."
	reasonDisabled    = "The repository is disabled."
)

// errWait stops a step that cannot go on this tick: the GitHub budget is
// spent, GitHub limits the App, agents are busy, the tick's time is up, or
// commands are still running. The next tick goes on from there.
var errWait = errors.New("waiting for the next tick")

// Tick advances resealing in this env by a bounded step: it starts due
// schedules, advances their runs, and refreshes the state of open reseal
// pull requests. Ticks may overlap, on several instances: starting a run is
// a conditional write, and a tick leases each run it advances, so each step
// happens once. It returns the errors it met, having done what it could.
func (s *Server) Tick(ctx context.Context) error {
	if s.repos == nil {
		return nil
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTickTime)
		defer cancel()
	}
	schedules, err := s.store.ResealSchedules(ctx)
	if err != nil {
		return err
	}
	tick := &tickState{s: s}
	var errs []error
	now := s.now().UTC()
	var active []string
	for _, sch := range schedules {
		id, err := s.startDue(ctx, sch, now)
		if err != nil {
			errs = append(errs, err)
		}
		if id == "" {
			id = sch.ActiveRunID
		}
		if id != "" {
			active = append(active, id)
		}
	}
	for _, id := range active {
		if tick.late(ctx) {
			break
		}
		if err := s.advanceRun(ctx, tick, id); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.refreshPulls(ctx, tick); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// startDue starts a schedule's run when it is due and has none active, and
// returns its ID. Its next run moves on by its interval, past now if runs
// were missed, in the same conditional write: of ticks that start the same
// run, one does.
func (s *Server) startDue(ctx context.Context, sch store.ResealSchedule, now time.Time) (string, error) {
	if !sch.Enabled || sch.NextRunAt == nil || sch.NextRunAt.After(now) || sch.ActiveRunID != "" {
		return "", nil
	}
	next := nextRunAfter(*sch.NextRunAt, sch.IntervalDays, now)
	run := newRun(sch, store.TriggerSchedule, sch.CreatedBy, now)
	err := s.store.StartResealRun(ctx, run, sch.NextRunAt, &next)
	switch {
	case errors.Is(err, store.ErrRunActive), errors.Is(err, store.ErrScheduleChanged):
		return "", nil
	case err != nil:
		return "", err
	}
	s.logRunStarted(ctx, run)
	return run.ID, nil
}

// nextRunAfter is the next run after a scheduled one at prev: an interval
// on, and on again until past now.
func nextRunAfter(prev time.Time, days int, now time.Time) time.Time {
	interval := time.Duration(max(days, 1)) * 24 * time.Hour
	next := prev.Add(interval)
	for !next.After(now) {
		next = next.Add(interval)
	}
	return next
}

// newRun is a schedule's new run.
func newRun(sch store.ResealSchedule, trigger, by string, now time.Time) store.ResealRun {
	return store.ResealRun{
		ID:           ulid.Make().String(),
		ScheduleID:   sch.ID,
		ScheduleName: sch.Name,
		CreatedBy:    sch.CreatedBy,
		CreatedByID:  sch.CreatedByID,
		Repos:        slices.Clone(sch.Repos),
		Orgs:         slices.Clone(sch.Orgs),
		Trigger:      trigger,
		RequestedBy:  by,
		Status:       store.RunQueued,
		StartedAt:    now,
	}
}

func (s *Server) logRunStarted(ctx context.Context, run store.ResealRun) {
	s.logger.InfoContext(ctx, "reseal run started",
		"event", "reseal.run_started", "env", s.env, "run_id", run.ID, "schedule_id", run.ScheduleID,
		"schedule", run.ScheduleName, "trigger", run.Trigger, "requested_by", run.RequestedBy,
		"repos", len(run.Repos), "orgs", run.Orgs)
}

// tickState is what one tick shares between the runs it advances: the
// agents it may send commands to, read once.
type tickState struct {
	s        *Server
	loaded   bool
	fleet    fleet.Fleet
	inFlight map[string]int
	loadErr  error
}

// late reports whether the tick should start no more work.
func (t *tickState) late(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	return ctx.Err() != nil || (ok && time.Until(deadline) < tickMargin)
}

// take counts n GitHub requests against the env's budget, and reports
// whether they may be made. More than a minute's budget is allowed in a
// minute nothing else used.
func (t *tickState) take(ctx context.Context, n int) bool {
	l := limitResealGitHub
	l.max = max(l.max-n+1, 1)
	now := t.s.now()
	return t.s.countRequests(ctx, l, l.name, n, now.Truncate(l.window).Add(l.window), now)
}

// resealer chooses the agent for a file's values, preferring its documents'
// regions and passing over agents with maxAgentQueue commands in flight,
// and returns it with the env key. errWait means every candidate is busy.
func (t *tickState) resealer(ctx context.Context, regions []string) (fleet.Agent, string, error) {
	if !t.loaded {
		t.loaded = true
		now := t.s.now().UTC()
		t.fleet, t.loadErr = t.s.loadFleet(ctx, now, false)
		t.inFlight = map[string]int{}
		for _, a := range t.fleet.Agents {
			if t.loadErr != nil || !a.Healthy {
				continue
			}
			cmds, err := t.s.openCommands(ctx, a.ID, now)
			if err != nil {
				t.loadErr = err
				break
			}
			t.inFlight[a.ID] = len(cmds)
		}
	}
	if t.loadErr != nil {
		return fleet.Agent{}, "", t.loadErr
	}
	a, err := fleet.ChooseResealer(t.fleet, regions, t.inFlight)
	if err == nil && t.inFlight[a.ID] >= maxAgentQueue {
		// the region's best is busy: any agent will do
		a, err = fleet.ChooseResealer(t.fleet, nil, t.inFlight)
		if err == nil && t.inFlight[a.ID] >= maxAgentQueue {
			return fleet.Agent{}, "", errWait
		}
	}
	if err != nil {
		return fleet.Agent{}, "", err
	}
	return a, t.fleet.EnvKey.Fingerprint, nil
}

// runStep is one tick's work on a run.
type runStep struct {
	s    *Server
	tick *tickState
	run  *store.ResealRun
	log  *slog.Logger
}

// advanceRun leases a run and advances it: it discovers its repositories,
// works on those in flight, starts more while it can, and finishes the run
// once every repository is done. It gives the lease up when it is done.
func (s *Server) advanceRun(ctx context.Context, tick *tickState, id string) error {
	now := s.now().UTC()
	run, ok, err := s.store.LeaseResealRun(ctx, id, now.Add(runLease), now)
	if err != nil || !ok {
		return err
	}
	held := run.LeaseUntil
	step := &runStep{s: s, tick: tick, run: &run, log: s.logger.With("env", s.env, "run_id", run.ID, "schedule_id", run.ScheduleID)}
	run.Status = store.RunRunning
	workErr := step.advance(ctx)
	if errors.Is(workErr, errWait) {
		workErr = nil
	}
	run.LeaseUntil = 0
	// the run's own record is saved even when the tick's time is up
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), tickMargin)
	defer cancel()
	saved, err := s.store.SaveResealRun(save, run, held)
	switch {
	case err != nil:
		return errors.Join(workErr, err)
	case !saved:
		// cancelled meanwhile: what it did stays, and nothing more is
		// queued
		step.log.InfoContext(ctx, "a run changed while a tick advanced it; leaving it")
		return workErr
	}
	if !run.Active() {
		step.logFinished(ctx)
	}
	return workErr
}

func (st *runStep) advance(ctx context.Context) error {
	if !st.run.Discovered {
		if err := st.discover(ctx); err != nil {
			return err
		}
	}
	var inFlight []string
	var firstErr error
	for _, key := range st.run.InFlight {
		done, err := st.advanceRepoKey(ctx, key)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if !done {
			inFlight = append(inFlight, key)
		}
	}
	st.run.InFlight = inFlight
	for firstErr == nil && len(st.run.InFlight) < maxReposInFlight && !st.tick.late(ctx) {
		next, err := st.s.store.NextResealRunRepos(ctx, st.run.ID, st.run.Cursor, 1)
		if err != nil {
			return err
		}
		if len(next) == 0 {
			break
		}
		st.run.Cursor = next[0].Key
		done, err := st.advanceRepo(ctx, next[0])
		firstErr = err
		if !done {
			st.run.InFlight = append(st.run.InFlight, next[0].Key)
		}
	}
	if firstErr != nil {
		return firstErr
	}
	if len(st.run.InFlight) == 0 && st.run.Outcomes.Done() >= st.run.Total {
		st.finish()
	}
	return nil
}

// finish ends the run with what its repositories came to.
func (st *runStep) finish() {
	r := st.run
	now := st.s.now().UTC()
	r.FinishedAt = &now
	switch o := r.Outcomes; {
	case r.Total == 0:
		r.Status = store.RunFailed
		if r.Error == "" {
			r.Error = "No repository is in the schedule's scope."
		}
	case o.Failed == r.Total:
		r.Status = store.RunFailed
	case o.Failed > 0:
		r.Status = store.RunPartial
	default:
		r.Status = store.RunSucceeded
	}
}

func (st *runStep) logFinished(ctx context.Context) {
	r := st.run
	level := slog.LevelInfo
	if r.Status != store.RunSucceeded {
		level = slog.LevelWarn
	}
	st.log.Log(ctx, level, "reseal run finished",
		"event", "reseal.run_finished", "status", r.Status, "schedule", r.ScheduleName, "repos", r.Total,
		"opened", r.Outcomes.Opened, "unchanged", r.Outcomes.Unchanged, "skipped", r.Outcomes.Skipped,
		"failed_repos", r.Outcomes.Failed, "resealed", r.Values.Resealed, "current", r.Values.Current,
		"failed", r.Values.Failed, "pull_requests", r.PullRequests, "error", r.Error)
}

// discover records the run's repositories: those the schedule lists, and
// every repository of the App's installation owned by one of its orgs,
// leaving out archived and disabled ones. A listed repository the App
// cannot reach fails. Past maxRunRepos, the rest are left out, and the run
// says so.
func (st *runStep) discover(ctx context.Context) error {
	r := st.run
	found := map[string]store.ResealRunRepo{}
	now := st.s.now().UTC()
	add := func(full, status, reason string) {
		key := strings.ToLower(full)
		if _, ok := found[key]; !ok {
			found[key] = store.ResealRunRepo{RunID: r.ID, Key: key, Repo: full, Status: status, Reason: reason, UpdatedAt: now}
		}
	}
	for _, full := range r.Repos {
		owner, name, _ := strings.Cut(full, "/")
		if !st.tick.take(ctx, 1) {
			return errWait
		}
		repo, err := st.s.repos.AppRepository(ctx, owner, name)
		switch {
		case errors.Is(err, repos.ErrNotFound):
			add(full, store.RepoFailed, reasonUnreachable)
			st.log.WarnContext(ctx, "repository not resealed", "event", "reseal.failed", "repository", full, "reason", reasonUnreachable)
		case err != nil:
			return st.githubError(ctx, err)
		case repo.Archived:
			add(repo.FullName, store.RepoSkipped, reasonArchived)
		case repo.Disabled:
			add(repo.FullName, store.RepoSkipped, reasonDisabled)
		default:
			add(repo.FullName, store.RepoPending, "")
		}
	}
	if len(r.Orgs) > 0 {
		if !st.tick.take(ctx, 1) {
			return errWait
		}
		installed, err := st.s.repos.AppInstalled(ctx)
		if err != nil {
			// a list cut short would leave repositories out unsaid
			return st.githubError(ctx, err)
		}
		for _, repo := range installed {
			in := slices.ContainsFunc(r.Orgs, func(org string) bool { return strings.EqualFold(org, repo.Owner) })
			if in && !repo.Archived && !repo.Disabled {
				add(repo.FullName, store.RepoPending, "")
			}
		}
	}
	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxRunRepos {
		r.Error = fmt.Sprintf("%d repositories are in scope, and a run covers at most %d: the first %d by name are in this run.", len(keys), maxRunRepos, maxRunRepos)
		keys = keys[:maxRunRepos]
	}
	list := make([]store.ResealRunRepo, len(keys))
	for i, k := range keys {
		list[i] = found[k]
	}
	if err := st.s.store.PutResealRunRepos(ctx, list); err != nil {
		return err
	}
	r.Discovered, r.Total = true, len(list)
	return nil
}

// githubError turns a GitHub failure into a wait when the App is rate
// limited or the request ran out of time, which the next tick retries.
func (st *runStep) githubError(ctx context.Context, err error) error {
	var limited *githubapp.RateLimitError
	switch {
	case errors.As(err, &limited):
		st.log.WarnContext(ctx, "github rate limit reached; the run waits", "event", "github.rate_limited", "retry_at", limited.RetryAt.UTC())
		return errWait
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return errWait
	}
	return err
}

// advanceRepoKey advances a repository in flight, and reports whether it is
// done.
func (st *runStep) advanceRepoKey(ctx context.Context, key string) (bool, error) {
	repo, found, err := st.s.store.ResealRunRepo(ctx, st.run.ID, key)
	if err != nil {
		return false, err
	}
	if !found {
		// it was never recorded: nothing to wait for
		return true, nil
	}
	return st.advanceRepo(ctx, repo)
}

// advanceRepo takes a repository as far as it can this tick and records
// it, and reports whether it is done; a repository done is counted in the
// run then, once, as it leaves the repositories in flight.
func (st *runStep) advanceRepo(ctx context.Context, repo store.ResealRunRepo) (bool, error) {
	if repo.Done() {
		st.count(repo)
		return true, nil
	}
	var work store.ResealWork
	if repo.Status != store.RepoPending {
		w, found, err := st.s.store.ResealWork(ctx, st.run.ID, repo.Key)
		if err != nil {
			return false, err
		}
		if !found {
			repo.Status = store.RepoPending
		}
		work = w
	}
	var err error
	for err == nil && !repo.Done() && !st.tick.late(ctx) {
		status := repo.Status
		switch status {
		case store.RepoPending:
			err = st.startRepo(ctx, &repo, &work)
		case store.RepoResealing:
			err = st.resealRepo(ctx, &repo, &work)
		case store.RepoOpening:
			err = st.openPull(ctx, &repo, &work)
		}
		if err == nil && repo.Status == status {
			// no further this tick
			break
		}
	}
	if errors.Is(err, errWait) {
		err = nil
	}
	repo.UpdatedAt = st.s.now().UTC()
	// what the tick did is recorded even when its time is up
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), tickMargin)
	defer cancel()
	if work.Commit != "" {
		if serr := st.s.store.PutResealWork(save, work); serr != nil {
			return false, errors.Join(err, serr)
		}
	}
	if serr := st.s.store.PutResealRunRepos(save, []store.ResealRunRepo{repo}); serr != nil {
		return false, errors.Join(err, serr)
	}
	if repo.Done() {
		if repo.Status == store.RepoFailed || repo.Values.Failed > 0 {
			st.log.WarnContext(ctx, "values or a repository not resealed",
				"event", "reseal.failed", "repository", repo.Repo, "status", repo.Status, "reason", repo.Reason,
				"resealed", repo.Values.Resealed, "failed", repo.Values.Failed)
		}
		st.count(repo)
	}
	return repo.Done(), err
}

// count adds a repository that is done to the run's totals.
func (st *runStep) count(repo store.ResealRunRepo) {
	o := &st.run.Outcomes
	switch repo.Status {
	case store.RepoOpened:
		o.Opened++
		st.run.PullRequests++
	case store.RepoUnchanged:
		o.Unchanged++
	case store.RepoSkipped:
		o.Skipped++
	default:
		o.Failed++
	}
	st.run.Values.Add(repo.Values)
}

// startRepo reads a repository's default branch and lists its candidate
// files, unless it is skipped: archived, disabled, or with a reseal pull
// request an earlier run opened still open.
func (st *runStep) startRepo(ctx context.Context, repo *store.ResealRunRepo, work *store.ResealWork) error {
	owner, name, _ := strings.Cut(repo.Repo, "/")
	if !st.tick.take(ctx, 1) {
		return errWait
	}
	r, err := st.s.repos.AppRepository(ctx, owner, name)
	switch {
	case errors.Is(err, repos.ErrNotFound):
		repo.Status, repo.Reason = store.RepoFailed, reasonUnreachable
		return nil
	case err != nil:
		return st.githubError(ctx, err)
	case r.Archived:
		repo.Status, repo.Reason = store.RepoSkipped, reasonArchived
		return nil
	case r.Disabled:
		repo.Status, repo.Reason = store.RepoSkipped, reasonDisabled
		return nil
	}
	repo.Repo = r.FullName
	open, found, err := st.openEarlier(ctx, repo.Key)
	if err != nil {
		return err
	}
	if found {
		repo.Status = store.RepoSkipped
		repo.Reason = fmt.Sprintf("Its reseal pull request #%d from an earlier run is still open; merge or close it first.", open.Number)
		repo.PullRequest = &store.ResealRunPull{Number: open.Number, URL: open.URL}
		return nil
	}
	if !st.tick.take(ctx, 2) {
		return errWait
	}
	head, err := st.s.repos.AppHead(ctx, r)
	if err != nil {
		return st.githubError(ctx, err)
	}
	candidates, truncated, err := st.s.repos.AppCandidates(ctx, r, head)
	if err != nil {
		return st.githubError(ctx, err)
	}
	*work = store.ResealWork{
		RunID: st.run.ID, Key: repo.Key, Owner: r.Owner, Name: r.Name, Branch: r.DefaultBranch, Commit: head,
		Candidates: []store.ResealFile{},
	}
	for _, c := range candidates {
		work.Candidates = append(work.Candidates, store.ResealFile{Path: c.Path, SHA: c.SHA, Mode: c.Mode})
	}
	if truncated {
		repo.Reason = "GitHub listed only part of this repository's files, or too many matched: files left out were not resealed."
	}
	repo.Status = store.RepoResealing
	return nil
}

// openEarlier returns a reseal pull request an earlier run opened in a
// repository that is still open, checking it on GitHub first when it was
// not checked lately.
func (st *runStep) openEarlier(ctx context.Context, repoKey string) (store.ResealPullRequest, bool, error) {
	prs, err := st.s.store.ResealPullRequests(ctx, true, repoKey)
	if err != nil {
		return store.ResealPullRequest{}, false, err
	}
	now := st.s.now().UTC()
	for _, p := range prs {
		if p.Source != store.SourceSchedule || p.RunID == st.run.ID {
			continue
		}
		if now.Sub(p.CheckedAt) > skipRecheck && st.tick.take(ctx, 1) {
			if fresh, err := st.s.refreshPull(ctx, p, now); err == nil {
				p = fresh
			}
		}
		if p.State == store.PullOpen {
			return p, true, nil
		}
	}
	return store.ResealPullRequest{}, false, nil
}

// resealRepo reads the repository's files a few a tick, sending each one's
// values to an agent as it reads it, and once every file is read and every
// command answered or expired, gathers what they did.
func (st *runStep) resealRepo(ctx context.Context, repo *store.ResealRunRepo, work *store.ResealWork) error {
	r := githubapp.Repository{Owner: work.Owner, Name: work.Name, FullName: repo.Repo, DefaultBranch: work.Branch}
	for work.Next < len(work.Candidates) {
		if st.tick.late(ctx) {
			return errWait
		}
		if len(work.Files) >= maxRunFiles {
			repo.Reason = fmt.Sprintf("A run reads at most %d files of a repository: the rest wait for a later run.", maxRunFiles)
			work.Next = len(work.Candidates)
			break
		}
		// an agent must be free before the file is read; for a while after
		// the run started, it waits for one to come back
		_, _, err := st.tick.resealer(ctx, nil)
		if _, refused := resealRefusal(err); errors.Is(err, errWait) || (refused && st.s.now().Sub(st.run.StartedAt) < agentWait) {
			return errWait
		}
		c := work.Candidates[work.Next]
		if !st.tick.take(ctx, 1) {
			return errWait
		}
		f, values, err := st.s.repos.AppFileValues(ctx, r, githubapp.TreeEntry{Path: c.Path, SHA: c.SHA, Mode: c.Mode, Type: "blob"})
		if err != nil {
			if werr := st.githubError(ctx, err); errors.Is(werr, errWait) {
				return werr
			}
			st.fail(repo, store.ResealFailure{Path: c.Path, Error: "The file could not be read from GitHub."})
			work.Next++
			continue
		}
		if f.Error != "" {
			st.fail(repo, store.ResealFailure{Path: c.Path, Error: "The file cannot be read: " + f.Error})
			work.Next++
			continue
		}
		if len(f.Documents) == 0 {
			work.Next++
			continue
		}
		if err := st.sendFile(ctx, repo, work, c, f.Documents, values); err != nil {
			return err
		}
		work.Next++
	}

	done, err := st.s.store.ResealBatchesDone(ctx, st.run.ID, repo.Key)
	if err != nil {
		return err
	}
	now := st.s.now().UTC()
	for _, c := range work.Commands {
		if !slices.Contains(done, c.ID) && now.Before(c.ExpiresAt.Add(resultGrace)) {
			// still running, or its result may still come
			return errWait
		}
	}
	return st.gather(ctx, repo, work)
}

// fail records a failure that is not one value's, such as a file that
// cannot be read, as one failed value.
func (st *runStep) fail(repo *store.ResealRunRepo, f store.ResealFailure) {
	repo.Values.Failed++
	if len(repo.Failures) < maxResealFailures {
		repo.Failures = append(repo.Failures, f)
	}
}

// sendFile sends a file's values to an agent, whole keys a command.
func (st *runStep) sendFile(ctx context.Context, repo *store.ResealRunRepo, work *store.ResealWork, c store.ResealFile, docs []manifest.Document, values []map[string]string) error {
	fileNo := len(work.Files)
	plan := planReseal(fileNo, c.Path, docs, values, nil)
	packs, tooLarge := packReseal(plan.groups)
	failures := plan.failures
	for _, g := range tooLarge {
		for _, v := range g.values {
			failures = append(failures, failure(c.Path, v.doc, v.key, errTooLargeToReseal))
		}
	}
	if len(packs) > 0 {
		agent, envKey, err := st.tick.resealer(ctx, regionsOf(plan.docs))
		if msg, refused := resealRefusal(err); refused {
			// the file's values cannot be resealed now: they fail, and a
			// later run tries them again
			for _, pack := range packs {
				for _, g := range pack {
					for _, v := range g.values {
						failures = append(failures, failure(c.Path, v.doc, v.key, msg))
					}
				}
			}
			packs = nil
		} else if err != nil {
			return err
		}
		now := st.s.now().UTC()
		for _, pack := range packs {
			cmd, err := resealCommand(agent.ID, ulid.Make().String(), resealPayload(envKey, pack), now)
			if err != nil {
				return err
			}
			cmd.RunID, cmd.RunRepo = st.run.ID, repo.Key
			if err := st.s.store.PutCommand(ctx, cmd); err != nil {
				return err
			}
			items := 0
			for _, g := range pack {
				items += len(g.values)
			}
			work.Commands = append(work.Commands, store.ResealCommand{ID: cmd.ID, AgentID: agent.ID, Items: items, ExpiresAt: cmd.ExpiresAt})
			st.tick.inFlight[agent.ID]++
		}
	}
	work.Files = append(work.Files, c)
	repo.Files++
	for _, f := range failures {
		st.fail(repo, f)
	}
	return nil
}

// resealedValue is a value a run's command resealed, for its pull request.
type resealedValue struct {
	file int
	repos.Target
	key        string
	ciphertext string
}

// collected is what a repository's commands did.
type collected struct {
	resealed []resealedValue
	counts   store.ResealCounts
	failures []store.ResealFailure
	from     []string
}

// collect reads what the repository's commands did: the values they
// resealed, and the counts and failures of the rest. A command that never
// answered fails its values.
func (st *runStep) collect(ctx context.Context, repoKey string, work *store.ResealWork) (collected, error) {
	var out collected
	path := func(file int) string {
		if file >= 0 && file < len(work.Files) {
			return work.Files[file].Path
		}
		return ""
	}
	for _, c := range work.Commands {
		b, found, err := st.s.store.ResealBatch(ctx, st.run.ID, repoKey, c.ID)
		if err != nil {
			return collected{}, err
		}
		if !found {
			out.counts.Failed += c.Items
			out.failures = append(out.failures, st.expiredFailures(ctx, c, path)...)
			continue
		}
		for _, it := range b.Items {
			file, doc, key, ok := parseResealItemID(it.ID)
			if !ok {
				out.counts.Failed++
				continue
			}
			switch it.Status {
			case protocol.ResealResealed:
				out.counts.Resealed++
				out.resealed = append(out.resealed, resealedValue{
					file: file, key: key, ciphertext: it.Ciphertext,
					Target: repos.Target{Namespace: it.Namespace, Name: it.Name, Scope: it.Scope, Index: doc},
				})
				if !slices.Contains(out.from, it.From) {
					out.from = append(out.from, it.From)
				}
			case protocol.ResealCurrent:
				out.counts.Current++
			default:
				out.counts.Failed++
				out.failures = append(out.failures, store.ResealFailure{Path: path(file), Key: key, Document: doc, Error: it.Error})
			}
		}
	}
	slices.Sort(out.from)
	return out, nil
}

// expiredFailures names the values of a command no agent answered, from its
// payload while that is kept.
func (st *runStep) expiredFailures(ctx context.Context, c store.ResealCommand, path func(int) string) []store.ResealFailure {
	raw, found, err := st.s.store.CommandPayload(ctx, c.ID)
	if err != nil || !found {
		return nil
	}
	var p protocol.ResealPayload
	if json.Unmarshal([]byte(raw), &p) != nil {
		return nil
	}
	var out []store.ResealFailure
	for _, it := range p.Items {
		file, doc, key, _ := parseResealItemID(it.ID)
		out = append(out, store.ResealFailure{Path: path(file), Key: key, Document: doc, Error: errNoAgentAnswered})
	}
	return out
}

// gather records what the repository's commands did, and moves it on: to
// opening its pull request when any value was resealed, and otherwise to
// unchanged, or failed when values failed.
func (st *runStep) gather(ctx context.Context, repo *store.ResealRunRepo, work *store.ResealWork) error {
	c, err := st.collect(ctx, repo.Key, work)
	if err != nil {
		return err
	}
	repo.Values.Add(c.counts)
	repo.FromKeys = c.from
	for _, f := range c.failures {
		if len(repo.Failures) < maxResealFailures {
			repo.Failures = append(repo.Failures, f)
		}
	}
	switch {
	case len(c.resealed) > 0:
		repo.Status = store.RepoOpening
	case repo.Values.Failed > 0:
		repo.Status = store.RepoFailed
		if repo.Reason == "" {
			repo.Reason = capitalize(plural(repo.Values.Failed, "value")) + " could not be resealed."
		}
	default:
		repo.Status = store.RepoUnchanged
	}
	return nil
}

// openPull opens the repository's pull request with every value resealed,
// in one commit on the run's branch, from the commit the run read.
func (st *runStep) openPull(ctx context.Context, repo *store.ResealRunRepo, work *store.ResealWork) error {
	c, err := st.collect(ctx, repo.Key, work)
	if err != nil {
		return err
	}
	byKey := map[[2]string]*repos.Value{}
	var order [][2]string
	files := map[int]bool{}
	for _, v := range c.resealed {
		if v.file < 0 || v.file >= len(work.Files) {
			continue
		}
		path := work.Files[v.file].Path
		k := [2]string{path, v.key}
		if byKey[k] == nil {
			byKey[k] = &repos.Value{Path: path, Key: v.key, ByIndex: true}
			order = append(order, k)
		}
		byKey[k].Targets = append(byKey[k].Targets, v.Target)
		byKey[k].Ciphertexts = append(byKey[k].Ciphertexts, v.ciphertext)
		files[v.file] = true
	}
	values := make([]repos.Value, len(order))
	for i, k := range order {
		values[i] = *byKey[k]
	}
	// a blob read and a blob written per file, then the tree, commit,
	// branch and pull request
	if !st.tick.take(ctx, 2*len(files)+6) {
		return errWait
	}
	text := st.s.runPullText(*st.run, work, values, c.from)
	r := githubapp.Repository{Owner: work.Owner, Name: work.Name, FullName: repo.Repo, DefaultBranch: work.Branch}
	pr, err := st.s.repos.AppOpenPullRequest(ctx, r, repos.NewPullRequest{
		Commit: work.Commit, Branch: runBranch(st.s.env, st.run.ID), Title: text.title, Body: text.body, Message: text.message, Values: values,
	})
	var fileErr *repos.FileError
	switch {
	case errors.As(err, &fileErr), errors.Is(err, githubapp.ErrBranchChanged):
		repo.Status, repo.Reason = store.RepoFailed, "Its pull request could not be opened: "+err.Error()
		return nil
	case err != nil:
		if werr := st.githubError(ctx, err); errors.Is(werr, errWait) {
			return werr
		}
		work.Attempts++
		work.LastError = err.Error()
		st.log.WarnContext(ctx, "failed to open a reseal pull request", "repository", repo.Repo, "attempt", work.Attempts, "error", err)
		if work.Attempts >= maxOpenAttempts {
			repo.Status, repo.Reason = store.RepoFailed, "Its pull request could not be opened: GitHub failed."
			return nil
		}
		return errWait
	}
	repo.Status = store.RepoOpened
	repo.PullRequest = &store.ResealRunPull{Number: pr.Number, URL: pr.URL}
	now := st.s.now().UTC()
	rec := store.ResealPullRequest{
		Repo: repo.Repo, Number: pr.Number, URL: pr.URL, Title: text.title, Branch: pr.Branch, State: store.PullOpen,
		Source: store.SourceSchedule, ScheduleID: st.run.ScheduleID, ScheduleName: st.run.ScheduleName, RunID: st.run.ID,
		RequestedBy: st.run.CreatedBy, OpenedAt: now, CheckedAt: now, Values: len(c.resealed), Files: len(files), FromKeys: c.from,
	}
	if err := st.s.store.PutResealPullRequest(ctx, rec); err != nil {
		return err
	}
	st.log.InfoContext(ctx, "reseal pull request opened",
		"event", "reseal.pr_opened", "source", store.SourceSchedule, "repository", repo.Repo, "number", pr.Number,
		"url", pr.URL, "values", len(c.resealed), "files", len(files), "from_keys", c.from)
	return nil
}

// runBranch names a run's branch: one per run, in every repository it
// opens a pull request in.
func runBranch(env, runID string) string {
	return "sealer/" + env + "/reseal-" + strings.ToLower(runID)
}

// runPullText writes a run's pull request: how many values in how many
// files moved from which keys to the env key, the schedule and who created
// it, and that resealing does not rotate values. Never a value or a
// ciphertext.
func (s *Server) runPullText(run store.ResealRun, work *store.ResealWork, values []repos.Value, from []string) prText {
	byPath := map[string][]string{}
	counts := map[string]int{}
	var paths []string
	n := 0
	for _, v := range values {
		if _, ok := byPath[v.Path]; !ok {
			paths = append(paths, v.Path)
		}
		byPath[v.Path] = append(byPath[v.Path], v.Key)
		counts[v.Path] += len(v.Targets)
		n += len(v.Targets)
	}
	sort.Strings(paths)
	in := plural(len(paths), "file")
	if len(paths) == 1 && len(plain(paths[0])) <= maxTitleLength/2 {
		in = plain(paths[0])
	}
	text := prText{title: fmt.Sprintf("Reseal %s in %s for %s", plural(n, "value"), in, s.env), files: len(paths), resealed: n, resealFiles: len(paths), fromKeys: from}

	keys := make([]string, len(from))
	for i, fp := range from {
		keys[i] = code(shortFingerprint(fp))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Resealed for the **%s** env with k8s-sealed-secrets-sealer by the schedule %s, which @%s created", s.env, code(run.ScheduleName), run.CreatedBy)
	if run.Trigger == store.TriggerManual {
		fmt.Fprintf(&b, ", run now by @%s", run.RequestedBy)
	}
	fmt.Fprintf(&b, " (run `%s`).\n\n", run.ID)
	fmt.Fprintf(&b, "%s in %s moved off %s onto the env key, unchanged.\n\n", capitalize(plural(n, "value")), plural(len(paths), "file"), strings.Join(keys, ", "))
	b.WriteString("| File | Keys | Values |\n| --- | --- | --- |\n")
	for _, p := range paths {
		ks := slices.Compact(slices.Sorted(slices.Values(byPath[p])))
		cells := make([]string, len(ks))
		for i, k := range ks {
			cells[i] = code(k)
		}
		fmt.Fprintf(&b, "| %s | %s | %d |\n", code(p), strings.Join(cells, ", "), counts[p])
	}
	fmt.Fprintf(&b, "\n%s Only `spec.encryptedData` changed. Based on `%s` at %s.\n", resealNote, work.Branch, work.Commit)
	text.body = b.String()

	var m strings.Builder
	m.WriteString(text.title + "\n\n")
	for _, p := range paths {
		ks := slices.Compact(slices.Sorted(slices.Values(byPath[p])))
		fmt.Fprintf(&m, "%s: %s\n", plain(p), strings.Join(ks, ", "))
	}
	fmt.Fprintf(&m, "\nResealed by the schedule %q.\n", plain(run.ScheduleName))
	fmt.Fprintf(&m, "\nRequested-by: %s <%d+%s@users.noreply.github.com>\n", run.CreatedBy, run.CreatedByID, run.CreatedBy)
	text.message = m.String()
	return text
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// recordRunResult records a reseal.v1 result of a run, for its repository:
// every item, with the document it is for, so the run can open its pull
// request from it once every command answered. A command that failed fails
// each of its values.
func (s *Server) recordRunResult(ctx context.Context, cmd store.CommandRecord, p protocol.ResealPayload, res protocol.ResealResult, status, errMsg string, _ time.Time) error {
	b := store.ResealBatch{RunID: cmd.RunID, RepoKey: cmd.RunRepo, CommandID: cmd.ID, Status: status, Error: errMsg}
	for i, it := range p.Items {
		item := store.ResealBatchItem{ID: it.ID, Namespace: it.Namespace, Name: it.Name, Scope: it.Scope, Status: protocol.ResealFailed, Error: errMsg}
		if status == protocol.CommandSucceeded && i < len(res.Items) {
			out := res.Items[i]
			item.Status, item.Ciphertext, item.From, item.Error = out.Status, out.Ciphertext, out.From, out.Error
		}
		b.Items = append(b.Items, item)
	}
	_, err := s.store.PutResealBatch(ctx, b)
	return err
}

// refreshPulls checks the state of open reseal pull requests on GitHub,
// the least recently checked first, those not checked for prRefreshTicks
// ticks, at most prRefreshPerTick.
func (s *Server) refreshPulls(ctx context.Context, tick *tickState) error {
	open, err := s.store.ResealPullRequests(ctx, true, "")
	if err != nil {
		return err
	}
	sort.SliceStable(open, func(i, j int) bool { return open[i].CheckedAt.Before(open[j].CheckedAt) })
	now := s.now().UTC()
	for i, p := range open {
		if i == prRefreshPerTick || now.Sub(p.CheckedAt) < prRefreshTicks*s.tickInterval || tick.late(ctx) || !tick.take(ctx, 1) {
			break
		}
		if _, err := s.refreshPull(ctx, p, now); err != nil {
			s.logger.WarnContext(ctx, "failed to check a reseal pull request", "env", s.env, "repository", p.Repo, "number", p.Number, "error", err)
		}
	}
	return nil
}

// refreshPull reads a reseal pull request's state from GitHub and records
// it, and returns it as recorded.
func (s *Server) refreshPull(ctx context.Context, p store.ResealPullRequest, now time.Time) (store.ResealPullRequest, error) {
	owner, name, _ := strings.Cut(p.Repo, "/")
	st, err := s.repos.PullRequestState(ctx, owner, name, p.Number)
	if err != nil && !errors.Is(err, githubapp.ErrNotFound) {
		return p, err
	}
	// one the App can no longer see stays open: it is checked again later
	p.CheckedAt = now
	if err == nil && !st.Open {
		p.State, p.ClosedAt = store.PullClosed, st.ClosedAt
		if st.Merged {
			p.State, p.MergedAt = store.PullMerged, st.MergedAt
		}
		if p.ClosedAt == nil {
			p.ClosedAt = &now
		}
	}
	updated, err := s.store.UpdateResealPullRequest(ctx, p)
	if err != nil || !updated || p.State == store.PullOpen {
		return p, err
	}
	event, msg := "reseal.pr_closed", "reseal pull request closed"
	if p.State == store.PullMerged {
		event, msg = "reseal.pr_merged", "reseal pull request merged"
	}
	s.logger.InfoContext(ctx, msg,
		"event", event, "env", s.env, "repository", p.Repo, "number", p.Number, "source", p.Source,
		"schedule_id", p.ScheduleID, "run_id", p.RunID, "values", p.Values)
	return p, nil
}
