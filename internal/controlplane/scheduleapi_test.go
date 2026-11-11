package controlplane

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

const schedulesPath = "/api/v1/reseal/schedules"

type schedulesResponse struct {
	Schedules []scheduleView `json:"schedules"`
}

type pullsResponse struct {
	PullRequests []resealPullView `json:"pull_requests"`
	Hidden       int              `json:"hidden"`
}

// asToken sends a GET with the admin token.
func (sh *sealHarness) asToken(path string) *httptest.ResponseRecorder {
	sh.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+harnessAdminToken)
	rec := httptest.NewRecorder()
	sh.h.ServeHTTP(rec, req)
	return rec
}

func (sh *sealHarness) createSchedule(body map[string]any) scheduleView {
	sh.t.Helper()
	rec := sh.do("alice", http.MethodPost, schedulesPath, body, true)
	if rec.Code != http.StatusCreated {
		sh.t.Fatalf("create schedule = %d %s", rec.Code, rec.Body)
	}
	return decode[scheduleView](sh.t, rec)
}

func TestSchedulesAPI(t *testing.T) {
	f := newResealFixture(t)
	sh := f.sh
	now := sh.clock()

	// for admins, with the CSRF token for changes
	for _, rec := range []*httptest.ResponseRecorder{
		sh.do("dave", http.MethodGet, schedulesPath, nil, false),
		sh.do("dave", http.MethodPost, schedulesPath, map[string]any{"name": "x", "repos": []string{"a/b"}, "interval_days": 1}, true),
		sh.do("dave", http.MethodGet, "/api/v1/reseal/runs", nil, false),
		sh.do("dave", http.MethodGet, "/api/v1/reseal/pull-requests", nil, false),
	} {
		if rec.Code != http.StatusForbidden {
			t.Fatalf("dave = %d %s", rec.Code, rec.Body)
		}
	}
	if rec := sh.do("alice", http.MethodPost, schedulesPath, map[string]any{"name": "x", "repos": []string{"a/b"}, "interval_days": 1}, false); rec.Code != http.StatusForbidden {
		t.Fatalf("without csrf = %d", rec.Code)
	}
	for name, body := range map[string]map[string]any{
		"no name":         {"repos": []string{"a/b"}, "interval_days": 1},
		"empty name":      {"name": " ", "repos": []string{"a/b"}, "interval_days": 1},
		"long name":       {"name": strings.Repeat("n", maxScheduleName+1), "repos": []string{"a/b"}, "interval_days": 1},
		"no interval":     {"name": "n", "repos": []string{"a/b"}},
		"interval 0":      {"name": "n", "repos": []string{"a/b"}, "interval_days": 0},
		"interval 366":    {"name": "n", "repos": []string{"a/b"}, "interval_days": 366},
		"no scope":        {"name": "n", "interval_days": 1},
		"not a repo":      {"name": "n", "repos": []string{"apps"}, "interval_days": 1},
		"not an org":      {"name": "n", "orgs": []string{"a b"}, "interval_days": 1},
		"too many orgs":   {"name": "n", "orgs": manyNames(maxScheduleOrgs + 1), "interval_days": 1},
		"unknown field":   {"name": "n", "repos": []string{"a/b"}, "interval_days": 1, "cron": "* * * * *"},
		"too many repos":  {"name": "n", "repos": manyRepos(maxScheduleRepos + 1), "interval_days": 1},
		"control in name": {"name": "a\nb", "repos": []string{"a/b"}, "interval_days": 1},
	} {
		if rec := sh.do("alice", http.MethodPost, schedulesPath, body, true); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}

	created := sh.createSchedule(map[string]any{
		"name": "every 75 days", "repos": []string{"example-org/apps", "Example-Org/Apps", "example-org/restricted"}, "interval_days": 75,
	})
	if created.ID == "" || !created.Enabled || !slices.Equal(created.Repos, []string{"example-org/apps", "example-org/restricted"}) ||
		len(created.Orgs) != 0 || created.CreatedBy != "alice" || created.NextRunAt == nil ||
		!created.NextRunAt.Equal(now.Add(75*24*time.Hour)) || created.LastRun != nil {
		t.Fatalf("created = %+v", created)
	}
	list := decode[schedulesResponse](t, sh.do("alice", http.MethodGet, schedulesPath, nil, false)).Schedules
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("schedules = %+v", list)
	}
	if token := decode[schedulesResponse](t, sh.asToken("/api/v1/admin/reseal/schedules")).Schedules; len(token) != 1 {
		t.Fatalf("schedules for the token = %+v", token)
	}

	// a change keeps the next run, unless the interval changes or the
	// schedule is turned off or on again
	patch := func(body map[string]any) scheduleView {
		t.Helper()
		sh.advance(time.Hour)
		rec := sh.do("alice", http.MethodPatch, schedulesPath+"/"+created.ID, body, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("patch %v = %d %s", body, rec.Code, rec.Body)
		}
		return decode[scheduleView](t, rec)
	}
	if got := patch(map[string]any{"name": "quarterly"}); got.Name != "quarterly" || !got.NextRunAt.Equal(*created.NextRunAt) || got.UpdatedBy != "alice" {
		t.Fatalf("renamed = %+v", got)
	}
	if got := patch(map[string]any{"interval_days": 75}); !got.NextRunAt.Equal(*created.NextRunAt) {
		t.Fatalf("same interval = %+v", got)
	}
	if got := patch(map[string]any{"interval_days": 30}); !got.NextRunAt.Equal(sh.clock().Add(30 * 24 * time.Hour)) {
		t.Fatalf("new interval = %+v", got)
	}
	if got := patch(map[string]any{"enabled": false}); got.Enabled || got.NextRunAt != nil {
		t.Fatalf("disabled = %+v", got)
	}
	if got := patch(map[string]any{"interval_days": 10}); got.NextRunAt != nil {
		t.Fatalf("a disabled schedule's new interval = %+v", got)
	}
	if got := patch(map[string]any{"enabled": true}); !got.Enabled || !got.NextRunAt.Equal(sh.clock().Add(10*24*time.Hour)) {
		t.Fatalf("enabled again = %+v", got)
	}
	if rec := sh.do("alice", http.MethodPatch, schedulesPath+"/"+created.ID, map[string]any{"repos": []string{}}, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("patch to no scope = %d", rec.Code)
	}
	if rec := sh.do("alice", http.MethodPatch, schedulesPath+"/01J00000000000000000000XXX", map[string]any{"name": "x"}, true); rec.Code != http.StatusNotFound {
		t.Fatalf("patch of an unknown schedule = %d", rec.Code)
	}

	// run now, once at a time, with the agents up
	f.checkInAll()
	rec := sh.do("alice", http.MethodPost, schedulesPath+"/"+created.ID+"/run", nil, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("run now = %d %s", rec.Code, rec.Body)
	}
	run := decode[runSummaryView](t, rec)
	if run.Status != "queued" || run.Trigger != "manual" || run.RequestedBy != "alice" || run.ScheduleName != "quarterly" {
		t.Fatalf("run = %+v", run)
	}
	if rec := sh.do("alice", http.MethodPost, schedulesPath+"/"+created.ID+"/run", nil, true); rec.Code != http.StatusConflict {
		t.Fatalf("run now while active = %d", rec.Code)
	}
	list = decode[schedulesResponse](t, sh.do("alice", http.MethodGet, schedulesPath, nil, false)).Schedules
	if list[0].ActiveRunID != run.ID || list[0].LastRun == nil || list[0].LastRun.ID != run.ID {
		t.Fatalf("schedule with its run = %+v", list[0])
	}
	sh.tick()
	f.runAgents()
	sh.tick()

	// alice cannot read example-org/restricted: it is hidden from her, not
	// from the token
	got := decode[runView](t, sh.do("alice", http.MethodGet, "/api/v1/reseal/runs/"+run.ID, nil, false))
	if got.Status != "succeeded" || got.Repos.Total != 2 || got.Repos.Done != 2 || got.Repos.Hidden != 1 || len(got.Repositories) != 1 ||
		got.Repositories[0].Repo != "example-org/apps" || got.Repositories[0].PullRequest == nil || got.Values.Resealed != 3 || got.PullRequests != 1 {
		t.Fatalf("run for alice = %+v", got)
	}
	if strings.Contains(sh.do("alice", http.MethodGet, "/api/v1/reseal/runs/"+run.ID, nil, false).Body.String(), "restricted") {
		t.Fatal("alice's view names a repository she cannot read")
	}
	token := decode[runView](t, sh.asToken("/api/v1/admin/reseal/runs/"+run.ID))
	if token.Repos.Hidden != 0 || len(token.Repositories) != 2 {
		t.Fatalf("run for the token = %+v", token)
	}
	runs := decode[struct {
		Runs []runSummaryView `json:"runs"`
	}](t, sh.do("alice", http.MethodGet, "/api/v1/reseal/runs?schedule="+created.ID+"&limit=5", nil, false)).Runs
	if len(runs) != 1 || runs[0].ID != run.ID {
		t.Fatalf("runs = %+v", runs)
	}
	if rec := sh.do("alice", http.MethodGet, "/api/v1/reseal/runs?limit=51", nil, false); rec.Code != http.StatusBadRequest {
		t.Fatalf("limit 51 = %d", rec.Code)
	}
	if rec := sh.do("alice", http.MethodGet, "/api/v1/reseal/runs/01J00000000000000000000XXX", nil, false); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown run = %d", rec.Code)
	}

	// the pull requests, open by default
	pulls := decode[pullsResponse](t, sh.do("alice", http.MethodGet, "/api/v1/reseal/pull-requests", nil, false))
	if len(pulls.PullRequests) != 1 || pulls.Hidden != 0 || pulls.PullRequests[0].Repo != "example-org/apps" ||
		pulls.PullRequests[0].Source != "schedule" || pulls.PullRequests[0].RunID != run.ID || pulls.PullRequests[0].State != "open" ||
		!slices.Equal(pulls.PullRequests[0].FromKeys, []string{f.old.Fingerprint}) {
		t.Fatalf("pull requests = %+v", pulls)
	}
	if merged := decode[pullsResponse](t, sh.do("alice", http.MethodGet, "/api/v1/reseal/pull-requests?state=merged", nil, false)); len(merged.PullRequests) != 0 {
		t.Fatalf("merged = %+v", merged)
	}
	if all := decode[pullsResponse](t, sh.asToken("/api/v1/admin/reseal/pull-requests?state=all")); len(all.PullRequests) != 1 {
		t.Fatalf("all for the token = %+v", all)
	}
	if rec := sh.do("alice", http.MethodGet, "/api/v1/reseal/pull-requests?state=draft", nil, false); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad state = %d", rec.Code)
	}

	// cancel a run, once
	rec = sh.do("alice", http.MethodPost, schedulesPath+"/"+created.ID+"/run", nil, true)
	second := decode[runSummaryView](t, rec)
	rec = sh.do("alice", http.MethodPost, "/api/v1/reseal/runs/"+second.ID+"/cancel", nil, true)
	if rec.Code != http.StatusOK || decode[runSummaryView](t, rec).Status != "cancelled" {
		t.Fatalf("cancel = %d %s", rec.Code, rec.Body)
	}
	if rec := sh.do("alice", http.MethodPost, "/api/v1/reseal/runs/"+second.ID+"/cancel", nil, true); rec.Code != http.StatusConflict {
		t.Fatalf("cancel again = %d", rec.Code)
	}

	// deleting a schedule cancels its active run
	rec = sh.do("alice", http.MethodPost, schedulesPath+"/"+created.ID+"/run", nil, true)
	third := decode[runSummaryView](t, rec)
	if rec := sh.do("alice", http.MethodDelete, schedulesPath+"/"+created.ID, nil, true); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if r := f.run(third.ID); r.Status != "cancelled" || r.CancelledBy != "alice" {
		t.Fatalf("run of the deleted schedule = %+v", r)
	}
	if rec := sh.do("alice", http.MethodDelete, schedulesPath+"/"+created.ID, nil, true); rec.Code != http.StatusNotFound {
		t.Fatalf("delete again = %d", rec.Code)
	}
	for _, event := range []string{"event=reseal.schedule_created", "event=reseal.schedule_updated", "event=reseal.schedule_deleted", "event=reseal.run_started", "event=reseal.run_finished"} {
		if !strings.Contains(sh.logs.String(), event) {
			t.Errorf("%s was not logged", event)
		}
	}
}

func TestSchedulesAPI_Cap(t *testing.T) {
	sh := newSealHarnessWith(t, resealCaps)
	sh.admins["alice"] = true
	for i := range maxSchedules {
		sh.createSchedule(map[string]any{"name": fmt.Sprintf("s%d", i), "orgs": []string{"example-org"}, "interval_days": 1})
	}
	rec := sh.do("alice", http.MethodPost, schedulesPath, map[string]any{"name": "one more", "orgs": []string{"example-org"}, "interval_days": 1}, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("one more = %d %s", rec.Code, rec.Body)
	}
}

func manyNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("org%d", i)
	}
	return out
}

func manyRepos(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("org/repo%d", i)
	}
	return out
}
