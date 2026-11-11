package controlplane

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// tick runs one tick and fails the test on an error.
func (sh *sealHarness) tick() {
	sh.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sh.srv.Tick(ctx); err != nil {
		sh.t.Fatalf("tick: %v", err)
	}
}

// runAgents runs every agent's reseal commands as the agents would.
func (f *resealFixture) runAgents() int {
	f.sh.t.Helper()
	n := 0
	for _, id := range slices.Sorted(maps.Keys(f.sh.agents)) {
		n += len(f.sh.runResealer(id, f.old, f.sh.key))
	}
	return n
}

// schedule stores a schedule of alice's, due a minute ago.
func (f *resealFixture) schedule(repos, orgs []string) store.ResealSchedule {
	f.sh.t.Helper()
	due := f.sh.clock().Add(-time.Minute)
	s := store.ResealSchedule{
		ID: ulid.Make().String(), Name: "every 75 days", Repos: repos, Orgs: orgs, IntervalDays: 75, Enabled: true,
		NextRunAt: &due, CreatedBy: "alice", CreatedByID: 1001, CreatedAt: f.sh.clock(),
	}
	if err := f.sh.store.CreateResealSchedule(context.Background(), s, maxSchedules); err != nil {
		f.sh.t.Fatal(err)
	}
	return s
}

func (f *resealFixture) run(id string) store.ResealRun {
	f.sh.t.Helper()
	r, ok, err := f.sh.store.ResealRun(context.Background(), id)
	if err != nil || !ok {
		f.sh.t.Fatalf("run %s: %v %v", id, ok, err)
	}
	return r
}

func (f *resealFixture) repo(runID, key string) store.ResealRunRepo {
	f.sh.t.Helper()
	r, ok, err := f.sh.store.ResealRunRepo(context.Background(), runID, key)
	if err != nil || !ok {
		f.sh.t.Fatalf("repository %s of run %s: %v %v", key, runID, ok, err)
	}
	return r
}

func TestResealRun(t *testing.T) {
	f := newResealFixture(t)
	sh := f.sh
	ctx := context.Background()
	sch := f.schedule([]string{"example-org/apps", "Example-Org/Apps", "example-org/missing"}, nil)

	// the due schedule starts a run, which reads the repositories and
	// sends their values to agents
	sh.tick()
	got, _, _ := sh.store.ResealSchedule(ctx, sch.ID)
	if got.ActiveRunID == "" || got.NextRunAt == nil || !got.NextRunAt.Equal(sch.NextRunAt.Add(75*24*time.Hour)) {
		t.Fatalf("schedule after the tick = %+v", got)
	}
	runID := got.ActiveRunID
	run := f.run(runID)
	if run.Status != store.RunRunning || !run.Discovered || run.Total != 2 || run.Trigger != store.TriggerSchedule || run.RequestedBy != "alice" {
		t.Fatalf("run = %+v", run)
	}
	if missing := f.repo(runID, "example-org/missing"); missing.Status != store.RepoFailed || missing.Reason != reasonUnreachable {
		t.Fatalf("missing = %+v", missing)
	}
	// billing, legacy, search, worker and the reseal fixture have documents
	// for dev
	if apps := f.repo(runID, "example-org/apps"); apps.Status != store.RepoResealing || apps.Files != 5 {
		t.Fatalf("apps = %+v", apps)
	}
	// nothing more happens until the agents answer
	sh.tick()
	if apps := f.repo(runID, "example-org/apps"); apps.Status != store.RepoResealing {
		t.Fatalf("apps before the agents answered = %+v", apps)
	}
	if n := f.runAgents(); n == 0 {
		t.Fatal("no agent was sent a command")
	}

	// once they have, one pull request with every resealed value
	sh.tick()
	apps := f.repo(runID, "example-org/apps")
	if apps.Status != store.RepoOpened || apps.PullRequest == nil || apps.PullRequest.Number != 1 ||
		apps.Values.Resealed != 3 || apps.Values.Current != 3 || apps.Values.Failed == 0 ||
		!slices.Equal(apps.FromKeys, []string{f.old.Fingerprint}) {
		t.Fatalf("apps = %+v", apps)
	}
	pull, ok := sh.github.PullRequest("example-org", "apps", 1)
	if !ok || pull.Head != runBranch("dev", runID) || pull.Title != "Reseal 3 values in "+resealPath+" for dev" ||
		len(pull.Files) != 1 || pull.Files[0].Path != resealPath {
		t.Fatalf("pull request = %+v", pull)
	}
	for _, want := range []string{"by the schedule `every 75 days`, which @alice created", "does not rotate them", "| `" + resealPath + "` | `old-token` | 3 |"} {
		if !strings.Contains(pull.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, pull.Body)
		}
	}
	if !strings.Contains(pull.Message, "Requested-by: alice <1001+alice@users.noreply.github.com>") {
		t.Errorf("message:\n%s", pull.Message)
	}
	before, after := encryptedData(t, pull.Files[0].Before), encryptedData(t, pull.Files[0].After)
	for i := range after {
		for key, v := range after[i] {
			if changed := v != before[i][key]; changed != (key == "old-token") {
				t.Errorf("document %d %s changed = %v", i, key, changed)
			}
		}
	}

	run = f.run(runID)
	if run.Status != store.RunPartial || run.FinishedAt == nil || run.PullRequests != 1 || run.Outcomes.Opened != 1 ||
		run.Outcomes.Failed != 1 || run.Values.Resealed != 3 || run.LeaseUntil != 0 {
		t.Fatalf("finished run = %+v", run)
	}
	if got, _, _ := sh.store.ResealSchedule(ctx, sch.ID); got.ActiveRunID != "" || got.LastRunID != runID {
		t.Fatalf("schedule after the run = %+v", got)
	}
	prs, _ := sh.store.ResealPullRequests(ctx, true, "")
	if len(prs) != 1 || prs[0].Source != store.SourceSchedule || prs[0].RunID != runID || prs[0].ScheduleName != "every 75 days" ||
		prs[0].Values != 3 || prs[0].Files != 1 || prs[0].RequestedBy != "alice" {
		t.Fatalf("reseal pull requests = %+v", prs)
	}

	// another run skips the repository while that pull request is open
	second := newRun(got, store.TriggerManual, "bob", sh.clock())
	if err := sh.store.StartResealRun(ctx, second, nil, nil); err != nil {
		t.Fatal(err)
	}
	sh.tick()
	skipped := f.repo(second.ID, "example-org/apps")
	if skipped.Status != store.RepoSkipped || skipped.PullRequest == nil || skipped.PullRequest.Number != 1 || !strings.Contains(skipped.Reason, "#1") {
		t.Fatalf("second run's apps = %+v", skipped)
	}
	if r := f.run(second.ID); r.Status != store.RunPartial || r.Outcomes.Skipped != 1 || r.PullRequests != 0 {
		t.Fatalf("second run = %+v", r)
	}

	// closed on GitHub, the tick sees it once it is due a check
	if !sh.github.ClosePullRequest("example-org", "apps", 1, false) {
		t.Fatal("close")
	}
	sh.tick()
	if open, _ := sh.store.ResealPullRequests(ctx, true, ""); len(open) != 1 {
		t.Fatalf("checked too soon: %+v", open)
	}
	sh.advance(prRefreshTicks*DefaultTickInterval + time.Second)
	sh.tick()
	if open, _ := sh.store.ResealPullRequests(ctx, true, ""); len(open) != 0 {
		t.Fatalf("still open: %+v", open)
	}
	done, _ := sh.store.ResealPullRequests(ctx, false, "")
	if len(done) != 1 || done[0].State != store.PullClosed || done[0].ClosedAt == nil {
		t.Fatalf("ended = %+v", done)
	}
	for _, event := range []string{"event=reseal.run_started", "event=reseal.run_finished", "event=reseal.pr_opened", "event=reseal.pr_closed", "event=reseal.failed"} {
		if !strings.Contains(sh.logs.String(), event) {
			t.Errorf("%s was not logged", event)
		}
	}
	for _, v := range f.values {
		if strings.Contains(sh.logs.String(), v) {
			t.Fatal("a value was logged")
		}
	}
}

// A run covers every repository of its orgs the App can reach, and values
// whose commands no agent answers fail once the commands expire.
func TestResealRun_OrgsAndExpiry(t *testing.T) {
	f := newResealFixture(t)
	sh := f.sh
	sch := f.schedule(nil, []string{"EXAMPLE-ORG"})
	sh.tick()
	got, _, _ := sh.store.ResealSchedule(context.Background(), sch.ID)
	run := f.run(got.ActiveRunID)
	if run.Total != 3 {
		t.Fatalf("run = %+v", run)
	}
	repos, _ := sh.store.ResealRunRepos(context.Background(), run.ID)
	var keys []string
	for _, r := range repos {
		keys = append(keys, r.Key)
	}
	if !slices.Equal(keys, []string{"example-org/apps", "example-org/platform", "example-org/restricted"}) {
		t.Fatalf("repositories = %v", keys)
	}
	// no agent answers: once the commands expire, their values fail
	sh.advance(resealCommandTTL + resultGrace + time.Second)
	for range 3 {
		sh.tick()
	}
	run = f.run(run.ID)
	apps := f.repo(run.ID, "example-org/apps")
	if apps.Status != store.RepoFailed || apps.Values.Resealed != 0 || apps.Values.Failed == 0 ||
		!slices.ContainsFunc(apps.Failures, func(fl store.ResealFailure) bool { return fl.Error == errNoAgentAnswered && fl.Path == resealPath }) {
		t.Fatalf("apps = %+v", apps)
	}
	if run.Status == store.RunRunning || run.Status == store.RunQueued {
		t.Fatalf("run = %+v", run)
	}
}

// A cancelled run queues nothing more, and its tick's save is refused.
func TestResealRun_Cancelled(t *testing.T) {
	f := newResealFixture(t)
	sh := f.sh
	sch := f.schedule([]string{"example-org/apps"}, nil)
	// not due: only the run below is there to advance
	sch.Enabled, sch.NextRunAt = false, nil
	if ok, err := sh.store.UpdateResealSchedule(context.Background(), sch); err != nil || !ok {
		t.Fatal(ok, err)
	}
	run := newRun(sch, store.TriggerManual, "alice", sh.clock())
	if err := sh.store.StartResealRun(context.Background(), run, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := sh.store.CancelResealRun(context.Background(), run.ID, "alice", sh.clock()); !ok {
		t.Fatal("cancel")
	}
	sh.tick()
	if r := f.run(run.ID); r.Status != store.RunCancelled || r.Discovered {
		t.Fatalf("run = %+v", r)
	}
	if n := f.runAgents(); n != 0 {
		t.Fatalf("%d commands were sent for a cancelled run", n)
	}
}

func TestNextRunAfter(t *testing.T) {
	prev := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		now  time.Time
		want time.Time
	}{
		{prev.Add(time.Hour), prev.Add(75 * 24 * time.Hour)},
		// runs were missed: the next is past now, on the schedule
		{prev.Add(200 * 24 * time.Hour), prev.Add(225 * 24 * time.Hour)},
	} {
		if got := nextRunAfter(prev, 75, tc.now); !got.Equal(tc.want) {
			t.Errorf("nextRunAfter(%s) = %s, want %s", tc.now, got, tc.want)
		}
	}
}
