package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// Schedule limits.
const (
	maxScheduleName     = 100
	maxScheduleRepos    = 100
	maxScheduleOrgs     = 20
	maxIntervalDays     = 365
	maxScheduleBody     = 64 << 10
	defaultRunsListed   = 20
	maxRunsListed       = 50
	resealViewTimeout   = 20 * time.Second
	errScheduleNotFound = "schedule not found"
	errRunNotFound      = "run not found"
)

// limitResealViews bounds the run and pull request views, which check the
// viewer's permission on each repository they name.
var limitResealViews = rateLimit{name: "reseal-views", max: 60, window: time.Minute}

// scheduleView is a schedule as admins see it.
type scheduleView struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Repos        []string   `json:"repos"`
	Orgs         []string   `json:"orgs"`
	IntervalDays int        `json:"interval_days"`
	Enabled      bool       `json:"enabled"`
	NextRunAt    *time.Time `json:"next_run_at"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedBy    string     `json:"updated_by,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
	// LastRun is its latest run; ActiveRunID is set while one is queued or
	// running.
	LastRun     *runSummaryView `json:"last_run,omitempty"`
	ActiveRunID string          `json:"active_run_id,omitempty"`
}

// runSummaryView is a run without its repositories.
type runSummaryView struct {
	ID           string     `json:"id"`
	ScheduleID   string     `json:"schedule_id"`
	ScheduleName string     `json:"schedule_name"`
	Trigger      string     `json:"trigger"`
	RequestedBy  string     `json:"requested_by"`
	Status       string     `json:"status"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	Repos        struct {
		Total int `json:"total"`
		Done  int `json:"done"`
		// Hidden counts the repositories the viewer cannot read, in a
		// run's details; a list of runs names no repository, and says 0.
		Hidden int `json:"hidden"`
	} `json:"repos"`
	Values       store.ResealCounts `json:"values"`
	PullRequests int                `json:"pull_requests"`
	Error        string             `json:"error,omitempty"`
}

// runView is a run with the repositories the viewer can read.
type runView struct {
	runSummaryView
	Repositories []runRepoView `json:"repositories"`
}

type runRepoView struct {
	Repo        string                `json:"repo"`
	Status      string                `json:"status"`
	Files       int                   `json:"files"`
	Values      store.ResealCounts    `json:"values"`
	PullRequest *store.ResealRunPull  `json:"pull_request,omitempty"`
	Reason      string                `json:"reason,omitempty"`
	Failures    []store.ResealFailure `json:"failures,omitempty"`
}

// resealPullView is a reseal pull request as admins see it.
type resealPullView struct {
	Repo         string     `json:"repo"`
	Number       int        `json:"number"`
	URL          string     `json:"url"`
	Title        string     `json:"title"`
	Branch       string     `json:"branch"`
	State        string     `json:"state"`
	Source       string     `json:"source"`
	ScheduleID   string     `json:"schedule_id,omitempty"`
	ScheduleName string     `json:"schedule_name,omitempty"`
	RunID        string     `json:"run_id,omitempty"`
	RequestedBy  string     `json:"requested_by"`
	OpenedAt     time.Time  `json:"opened_at"`
	MergedAt     *time.Time `json:"merged_at,omitempty"`
	ClosedAt     *time.Time `json:"closed_at,omitempty"`
	CheckedAt    time.Time  `json:"checked_at"`
	Values       int        `json:"values"`
	Files        int        `json:"files"`
	FromKeys     []string   `json:"from_keys"`
}

func viewRunSummary(r store.ResealRun) runSummaryView {
	v := runSummaryView{
		ID: r.ID, ScheduleID: r.ScheduleID, ScheduleName: r.ScheduleName, Trigger: r.Trigger, RequestedBy: r.RequestedBy,
		Status: r.Status, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Values: r.Values, PullRequests: r.PullRequests, Error: r.Error,
	}
	v.Repos.Total, v.Repos.Done = r.Total, r.Outcomes.Done()
	return v
}

func viewSchedule(s store.ResealSchedule, last *store.ResealRun) scheduleView {
	v := scheduleView{
		ID: s.ID, Name: s.Name, Repos: nonNil(s.Repos), Orgs: nonNil(s.Orgs), IntervalDays: s.IntervalDays, Enabled: s.Enabled,
		NextRunAt: s.NextRunAt, CreatedBy: s.CreatedBy, CreatedAt: s.CreatedAt, UpdatedBy: s.UpdatedBy, UpdatedAt: s.UpdatedAt,
		ActiveRunID: s.ActiveRunID,
	}
	if last != nil {
		summary := viewRunSummary(*last)
		v.LastRun = &summary
	}
	return v
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// listSchedules serves the env's schedules, each with its latest run.
func (s *Server) listSchedules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	schedules, err := s.store.ResealSchedules(ctx)
	if err != nil {
		s.internalError(w, r, "failed to read schedules", err)
		return
	}
	out := make([]scheduleView, 0, len(schedules))
	for _, sch := range schedules {
		var last *store.ResealRun
		if sch.LastRunID != "" {
			run, found, err := s.store.ResealRun(ctx, sch.LastRunID)
			if err != nil {
				s.internalError(w, r, "failed to read run", err)
				return
			}
			if found {
				last = &run
			}
		}
		out = append(out, viewSchedule(sch, last))
	}
	httpserver.WriteJSON(w, http.StatusOK, map[string]any{"schedules": out})
}

// scheduleInput is what an admin sets on a schedule; a PATCH sets the
// fields it names.
type scheduleInput struct {
	Name         *string   `json:"name"`
	Repos        *[]string `json:"repos"`
	Orgs         *[]string `json:"orgs"`
	IntervalDays *int      `json:"interval_days"`
	Enabled      *bool     `json:"enabled"`
}

// apply sets the input's fields on a schedule and checks it, returning a
// sentence for a 400.
func (in scheduleInput) apply(s *store.ResealSchedule) string {
	if in.Name != nil {
		s.Name = strings.TrimSpace(*in.Name)
	}
	if in.Repos != nil {
		s.Repos = nil
		for _, full := range *in.Repos {
			full = strings.TrimSpace(full)
			owner, name, ok := strings.Cut(full, "/")
			if !ok || !githubapp.ValidName(owner) || !githubapp.ValidName(name) {
				return fmt.Sprintf("%q is not a repository: name it as owner/name", plain(full))
			}
			if !slices.ContainsFunc(s.Repos, func(r string) bool { return strings.EqualFold(r, full) }) {
				s.Repos = append(s.Repos, full)
			}
		}
	}
	if in.Orgs != nil {
		s.Orgs = nil
		for _, org := range *in.Orgs {
			org = strings.TrimSpace(org)
			if !githubapp.ValidName(org) {
				return fmt.Sprintf("%q is not an organization name", plain(org))
			}
			if !slices.ContainsFunc(s.Orgs, func(o string) bool { return strings.EqualFold(o, org) }) {
				s.Orgs = append(s.Orgs, org)
			}
		}
	}
	if in.IntervalDays != nil {
		s.IntervalDays = *in.IntervalDays
	}
	if in.Enabled != nil {
		s.Enabled = *in.Enabled
	}
	switch n := utf8.RuneCountInString(s.Name); {
	case n == 0 || n > maxScheduleName:
		return fmt.Sprintf("name must be 1 to %d characters", maxScheduleName)
	case strings.ContainsFunc(s.Name, unicode.IsControl):
		return "name must be one line of text"
	case len(s.Repos) > maxScheduleRepos:
		return fmt.Sprintf("a schedule names at most %d repositories", maxScheduleRepos)
	case len(s.Orgs) > maxScheduleOrgs:
		return fmt.Sprintf("a schedule names at most %d organizations", maxScheduleOrgs)
	case len(s.Repos) == 0 && len(s.Orgs) == 0:
		return "name at least one repository or organization"
	case s.IntervalDays < 1 || s.IntervalDays > maxIntervalDays:
		return fmt.Sprintf("interval_days must be 1 to %d", maxIntervalDays)
	}
	return ""
}

// intervalFrom is when an interval of days from now ends.
func intervalFrom(now time.Time, days int) *time.Time {
	t := now.Add(time.Duration(days) * 24 * time.Hour)
	return &t
}

// createSchedule creates a schedule; its first run is an interval from now.
func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request) {
	var in scheduleInput
	if !decodeJSON(w, r, maxScheduleBody, &in) {
		return
	}
	if in.Name == nil || in.IntervalDays == nil {
		writeError(w, http.StatusBadRequest, "name and interval_days are required")
		return
	}
	ctx := r.Context()
	user := userauth.UserFrom(ctx)
	now := s.now().UTC()
	sch := store.ResealSchedule{
		ID: ulid.Make().String(), Repos: []string{}, Orgs: []string{}, Enabled: true,
		CreatedBy: user.Login, CreatedByID: user.ID, CreatedAt: now,
	}
	if msg := in.apply(&sch); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if sch.Enabled {
		sch.NextRunAt = intervalFrom(now, sch.IntervalDays)
	}
	err := s.store.CreateResealSchedule(ctx, sch, maxSchedules)
	switch {
	case errors.Is(err, store.ErrTooManySchedules):
		writeError(w, http.StatusConflict, fmt.Sprintf("this env has %d schedules, the most it can; delete one first", maxSchedules))
		return
	case err != nil:
		s.internalError(w, r, "failed to create schedule", err)
		return
	}
	s.logger.InfoContext(ctx, "reseal schedule created",
		"event", "reseal.schedule_created", "env", s.env, "schedule_id", sch.ID, "schedule", sch.Name, "user", user.Login,
		"user_id", user.ID, "repos", sch.Repos, "orgs", sch.Orgs, "interval_days", sch.IntervalDays, "enabled", sch.Enabled)
	httpserver.WriteJSON(w, http.StatusCreated, viewSchedule(sch, nil))
}

// requestedSchedule reads the schedule the path names, answering 404 for
// one that does not exist.
func (s *Server) requestedSchedule(w http.ResponseWriter, r *http.Request) (store.ResealSchedule, bool) {
	id := r.PathValue("id")
	if _, err := ulid.ParseStrict(id); err != nil {
		writeError(w, http.StatusNotFound, errScheduleNotFound)
		return store.ResealSchedule{}, false
	}
	sch, found, err := s.store.ResealSchedule(r.Context(), id)
	if err != nil {
		s.internalError(w, r, "failed to read schedule", err)
		return store.ResealSchedule{}, false
	}
	if !found {
		writeError(w, http.StatusNotFound, errScheduleNotFound)
		return store.ResealSchedule{}, false
	}
	return sch, true
}

// updateSchedule changes the fields a request names. The next run stays,
// unless the interval changed (an interval from now) or the schedule is
// enabled again (likewise); disabling it clears the next run.
func (s *Server) updateSchedule(w http.ResponseWriter, r *http.Request) {
	var in scheduleInput
	if !decodeJSON(w, r, maxScheduleBody, &in) {
		return
	}
	sch, ok := s.requestedSchedule(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	user := userauth.UserFrom(ctx)
	now := s.now().UTC()
	was := sch
	if msg := in.apply(&sch); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	switch {
	case !sch.Enabled:
		sch.NextRunAt = nil
	case !was.Enabled, sch.IntervalDays != was.IntervalDays, sch.NextRunAt == nil:
		sch.NextRunAt = intervalFrom(now, sch.IntervalDays)
	}
	sch.UpdatedBy, sch.UpdatedAt = user.Login, &now
	updated, err := s.store.UpdateResealSchedule(ctx, sch)
	if err != nil {
		s.internalError(w, r, "failed to update schedule", err)
		return
	}
	if !updated {
		writeError(w, http.StatusNotFound, errScheduleNotFound)
		return
	}
	s.logger.InfoContext(ctx, "reseal schedule updated",
		"event", "reseal.schedule_updated", "env", s.env, "schedule_id", sch.ID, "schedule", sch.Name, "user", user.Login,
		"user_id", user.ID, "repos", sch.Repos, "orgs", sch.Orgs, "interval_days", sch.IntervalDays, "enabled", sch.Enabled)
	s.writeSchedule(w, r, http.StatusOK, sch.ID)
}

// writeSchedule answers with a schedule as stored.
func (s *Server) writeSchedule(w http.ResponseWriter, r *http.Request, status int, id string) {
	ctx := r.Context()
	sch, found, err := s.store.ResealSchedule(ctx, id)
	if err != nil || !found {
		s.internalError(w, r, "failed to read schedule", err)
		return
	}
	var last *store.ResealRun
	if sch.LastRunID != "" {
		run, found, err := s.store.ResealRun(ctx, sch.LastRunID)
		if err != nil {
			s.internalError(w, r, "failed to read run", err)
			return
		}
		if found {
			last = &run
		}
	}
	httpserver.WriteJSON(w, status, viewSchedule(sch, last))
}

// deleteSchedule deletes a schedule and cancels its active run. Pull
// requests its runs opened stay, and so do its runs' records.
func (s *Server) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := ulid.ParseStrict(id); err != nil {
		writeError(w, http.StatusNotFound, errScheduleNotFound)
		return
	}
	ctx := r.Context()
	user := userauth.UserFrom(ctx)
	sch, found, err := s.store.DeleteResealSchedule(ctx, id)
	if err != nil {
		s.internalError(w, r, "failed to delete schedule", err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, errScheduleNotFound)
		return
	}
	if sch.ActiveRunID != "" {
		// ticks advance a schedule's run, so one left active would never end
		if run, cancelled, err := s.store.CancelResealRun(ctx, sch.ActiveRunID, user.Login, s.now().UTC()); err != nil {
			s.logger.ErrorContext(ctx, "failed to cancel the run of a deleted schedule", "env", s.env, "run_id", sch.ActiveRunID, "error", err)
		} else if cancelled {
			s.logRunCancelled(ctx, run, user)
		}
	}
	s.logger.InfoContext(ctx, "reseal schedule deleted",
		"event", "reseal.schedule_deleted", "env", s.env, "schedule_id", sch.ID, "schedule", sch.Name, "user", user.Login, "user_id", user.ID)
	w.WriteHeader(http.StatusNoContent)
}

// runSchedule starts a run of a schedule now, unless one is active. The
// next tick takes it up; its next scheduled run stays as it was.
func (s *Server) runSchedule(w http.ResponseWriter, r *http.Request) {
	sch, ok := s.requestedSchedule(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	user := userauth.UserFrom(ctx)
	run := newRun(sch, store.TriggerManual, user.Login, s.now().UTC())
	err := s.store.StartResealRun(ctx, run, nil, nil)
	switch {
	case errors.Is(err, store.ErrRunActive):
		writeError(w, http.StatusConflict, "a run of this schedule is queued or running; wait for it to finish, or cancel it")
		return
	case errors.Is(err, store.ErrScheduleChanged):
		writeError(w, http.StatusNotFound, errScheduleNotFound)
		return
	case err != nil:
		s.internalError(w, r, "failed to start a run", err)
		return
	}
	s.logRunStarted(ctx, run)
	httpserver.WriteJSON(w, http.StatusAccepted, viewRunSummary(run))
}

// listRuns serves runs, newest first, of one schedule when ?schedule= names
// it, at most ?limit= (20 by default, 50 at most).
func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := defaultRunsListed
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxRunsListed {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("limit must be 1 to %d", maxRunsListed))
			return
		}
		limit = n
	}
	schedule := q.Get("schedule")
	if schedule != "" {
		if _, err := ulid.ParseStrict(schedule); err != nil {
			httpserver.WriteJSON(w, http.StatusOK, map[string]any{"runs": []runSummaryView{}})
			return
		}
	}
	runs, err := s.store.ResealRuns(r.Context(), schedule, limit)
	if err != nil {
		s.internalError(w, r, "failed to read runs", err)
		return
	}
	out := make([]runSummaryView, len(runs))
	for i, run := range runs {
		out[i] = viewRunSummary(run)
	}
	httpserver.WriteJSON(w, http.StatusOK, map[string]any{"runs": out})
}

// requestedRun reads the run the path names.
func (s *Server) requestedRun(w http.ResponseWriter, r *http.Request) (store.ResealRun, bool) {
	id := r.PathValue("id")
	if _, err := ulid.ParseStrict(id); err != nil {
		writeError(w, http.StatusNotFound, errRunNotFound)
		return store.ResealRun{}, false
	}
	run, found, err := s.store.ResealRun(r.Context(), id)
	if err != nil {
		s.internalError(w, r, "failed to read run", err)
		return store.ResealRun{}, false
	}
	if !found {
		writeError(w, http.StatusNotFound, errRunNotFound)
		return store.ResealRun{}, false
	}
	return run, true
}

// getRun serves a run with the repositories the viewer can read; the rest
// count as hidden.
func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	run, ok := s.requestedRun(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), resealViewTimeout)
	defer cancel()
	repos, err := s.store.ResealRunRepos(ctx, run.ID)
	if err != nil {
		s.internalError(w, r, "failed to read the run's repositories", err)
		return
	}
	names := make([]string, len(repos))
	for i, repo := range repos {
		names[i] = repo.Repo
	}
	readable, ok := s.readable(w, r, names)
	if !ok {
		return
	}
	v := runView{runSummaryView: viewRunSummary(run), Repositories: []runRepoView{}}
	for _, repo := range repos {
		if !readable(repo.Repo) {
			v.Repos.Hidden++
			continue
		}
		v.Repositories = append(v.Repositories, runRepoView{
			Repo: repo.Repo, Status: repo.Status, Files: repo.Files, Values: repo.Values,
			PullRequest: repo.PullRequest, Reason: repo.Reason, Failures: repo.Failures,
		})
	}
	// before discovery, or for repositories not counted yet
	v.Repos.Total = max(v.Repos.Total, len(repos))
	httpserver.WriteJSON(w, http.StatusOK, v)
}

// readable returns whether the viewer may see each repository: every one
// for the admin token, and for a user those they can read on GitHub, as
// the repository list checks them. The lookups count against the user's
// limitRepoChecks; with that spent, it answers 429 and reports false.
func (s *Server) readable(w http.ResponseWriter, r *http.Request, names []string) (func(string) bool, bool) {
	user := userauth.UserFrom(r.Context())
	if user == nil {
		return func(string) bool { return true }, true
	}
	key, _ := limitKey(r, limitRepoChecks)
	if !s.admit(w, r, limitRepoChecks, key, 0) {
		return nil, false
	}
	slices.Sort(names)
	ok, lookups := s.repos.Readable(r.Context(), user, slices.Compact(names))
	s.charge(r.Context(), limitRepoChecks, key, lookups)
	return func(name string) bool { return ok[strings.ToLower(name)] }, true
}

// cancelRun cancels an active run: it queues nothing more, its commands
// in flight are left to expire, and pull requests it opened stay.
func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	run, ok := s.requestedRun(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	user := userauth.UserFrom(ctx)
	cancelled, ok, err := s.store.CancelResealRun(ctx, run.ID, user.Login, s.now().UTC())
	if err != nil {
		s.internalError(w, r, "failed to cancel run", err)
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "the run is not queued or running")
		return
	}
	s.logRunCancelled(ctx, cancelled, user)
	httpserver.WriteJSON(w, http.StatusOK, viewRunSummary(cancelled))
}

func (s *Server) logRunCancelled(ctx context.Context, run store.ResealRun, user *userauth.User) {
	s.logger.WarnContext(ctx, "reseal run cancelled",
		"event", "reseal.run_finished", "env", s.env, "run_id", run.ID, "schedule_id", run.ScheduleID, "schedule", run.ScheduleName,
		"status", run.Status, "user", user.Login, "user_id", user.ID, "repos", run.Total, "resealed", run.Values.Resealed,
		"current", run.Values.Current, "failed", run.Values.Failed, "pull_requests", run.PullRequests)
}

// listResealPulls serves reseal pull requests in ?state= (open, merged,
// closed or all; open by default), newest first, of the repositories the
// viewer can read; hidden counts the rest.
func (s *Server) listResealPulls(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		state = store.PullOpen
	}
	if !slices.Contains([]string{store.PullOpen, store.PullMerged, store.PullClosed, "all"}, state) {
		writeError(w, http.StatusBadRequest, "state must be open, merged, closed or all")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), resealViewTimeout)
	defer cancel()
	var prs []store.ResealPullRequest
	if state == store.PullOpen || state == "all" {
		open, err := s.store.ResealPullRequests(ctx, true, "")
		if err != nil {
			s.internalError(w, r, "failed to read reseal pull requests", err)
			return
		}
		prs = append(prs, open...)
	}
	if state != store.PullOpen {
		ended, err := s.store.ResealPullRequests(ctx, false, "")
		if err != nil {
			s.internalError(w, r, "failed to read reseal pull requests", err)
			return
		}
		for _, p := range ended {
			if state == "all" || p.State == state {
				prs = append(prs, p)
			}
		}
	}
	names := make([]string, len(prs))
	for i, p := range prs {
		names[i] = p.Repo
	}
	readable, ok := s.readable(w, r.WithContext(ctx), names)
	if !ok {
		return
	}
	sort.SliceStable(prs, func(i, j int) bool { return prs[i].OpenedAt.After(prs[j].OpenedAt) })
	out := []resealPullView{}
	hidden := 0
	for _, p := range prs {
		if !readable(p.Repo) {
			hidden++
			continue
		}
		out = append(out, resealPullView{
			Repo: p.Repo, Number: p.Number, URL: p.URL, Title: p.Title, Branch: p.Branch, State: p.State, Source: p.Source,
			ScheduleID: p.ScheduleID, ScheduleName: p.ScheduleName, RunID: p.RunID, RequestedBy: p.RequestedBy,
			OpenedAt: p.OpenedAt, MergedAt: p.MergedAt, ClosedAt: p.ClosedAt, CheckedAt: p.CheckedAt,
			Values: p.Values, Files: p.Files, FromKeys: nonNil(p.FromKeys),
		})
	}
	httpserver.WriteJSON(w, http.StatusOK, map[string]any{"pull_requests": out, "hidden": hidden})
}
