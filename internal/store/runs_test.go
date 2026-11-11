package store

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

func TestStore_ResealSchedules(t *testing.T) {
	// stores makes a table of its own: the cap is per table
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			next := now.Add(75 * 24 * time.Hour)
			sch := ResealSchedule{
				ID: ulid.Make().String(), Name: "quarterly", Repos: []string{"example-org/apps"}, Orgs: []string{"example-org"},
				IntervalDays: 75, Enabled: true, NextRunAt: &next, CreatedBy: "alice", CreatedByID: 1001, CreatedAt: now,
			}
			if err := s.CreateResealSchedule(ctx, sch, 2); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.ResealSchedule(ctx, sch.ID)
			if err != nil || !ok || !reflect.DeepEqual(got, sch) {
				t.Fatalf("ResealSchedule = %+v, %v, %v", got, ok, err)
			}

			// a tick starts a due run and moves the next one on; an update
			// read before, that does not change the next run, keeps it
			moved := next.Add(75 * 24 * time.Hour)
			active := ResealRun{ID: ulid.Make().String(), ScheduleID: sch.ID, Status: RunQueued, StartedAt: now}
			if err := s.StartResealRun(ctx, active, &next, &moved); err != nil {
				t.Fatal(err)
			}
			stale := sch
			stale.Name = "renamed"
			if ok, err := s.UpdateResealSchedule(ctx, stale, false); err != nil || !ok {
				t.Fatalf("update: %v %v", ok, err)
			}
			if got, _, _ := s.ResealSchedule(ctx, sch.ID); got.Name != "renamed" || got.NextRunAt == nil || !got.NextRunAt.Equal(moved) {
				t.Fatalf("after an update that keeps the next run = %+v", got)
			}
			// an update changes what people set, and keeps its runs
			upd := sch
			upd.Name, upd.Repos, upd.Orgs, upd.IntervalDays, upd.Enabled, upd.NextRunAt = "monthly", nil, []string{"other-org"}, 30, false, nil
			upd.UpdatedBy, upd.UpdatedAt = "bob", ptr(now.Add(time.Minute))
			if ok, err := s.UpdateResealSchedule(ctx, upd, true); err != nil || !ok {
				t.Fatalf("update: %v %v", ok, err)
			}
			got, _, _ = s.ResealSchedule(ctx, sch.ID)
			if got.Name != "monthly" || len(got.Repos) != 0 || !slices.Equal(got.Orgs, []string{"other-org"}) || got.IntervalDays != 30 ||
				got.Enabled || got.NextRunAt != nil || got.UpdatedBy != "bob" || got.ActiveRunID == "" || got.LastRunID != got.ActiveRunID ||
				got.CreatedBy != "alice" {
				t.Fatalf("after update = %+v", got)
			}
			if ok, err := s.UpdateResealSchedule(ctx, ResealSchedule{ID: "missing"}, true); err != nil || ok {
				t.Fatalf("update of a missing schedule: %v %v", ok, err)
			}

			// at most two in this table
			second := sch
			second.ID = ulid.Make().String()
			if err := s.CreateResealSchedule(ctx, second, 2); err != nil {
				t.Fatal(err)
			}
			third := sch
			third.ID = ulid.Make().String()
			if err := s.CreateResealSchedule(ctx, third, 2); !errors.Is(err, ErrTooManySchedules) {
				t.Fatalf("a third: %v", err)
			}
			list, err := s.ResealSchedules(ctx)
			if err != nil || len(list) != 2 || list[0].ID != sch.ID || list[1].ID != second.ID {
				t.Fatalf("ResealSchedules = %+v, %v", list, err)
			}

			// deleting one makes room, and cancels its active run in the
			// same write
			gone, ok, err := s.DeleteResealSchedule(ctx, sch.ID, "alice", now)
			if err != nil || !ok || gone.Name != "monthly" || gone.ActiveRunID != active.ID {
				t.Fatalf("delete = %+v, %v, %v", gone, ok, err)
			}
			if run, _, _ := s.ResealRun(ctx, active.ID); run.Status != RunCancelled || run.CancelledBy != "alice" || run.FinishedAt == nil {
				t.Fatalf("the deleted schedule's run = %+v", run)
			}
			if _, ok, err := s.DeleteResealSchedule(ctx, sch.ID, "alice", now); err != nil || ok {
				t.Fatalf("delete again: %v %v", ok, err)
			}
			if err := s.CreateResealSchedule(ctx, third, 2); err != nil {
				t.Fatalf("after a delete: %v", err)
			}
		})
	}
}

// Of ticks that start the same due run, one does; a schedule has one
// active run at most.
func TestStore_StartResealRun(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			due := now.Add(-time.Minute)
			sch := ResealSchedule{ID: ulid.Make().String(), Name: "n", Repos: []string{"a/b"}, IntervalDays: 1, Enabled: true, NextRunAt: &due, CreatedAt: now}
			if err := s.CreateResealSchedule(ctx, sch, 1000); err != nil {
				t.Fatal(err)
			}
			next := due.Add(24 * time.Hour)
			var wg sync.WaitGroup
			errs := make([]error, 8)
			for i := range errs {
				wg.Go(func() {
					run := ResealRun{ID: ulid.Make().String(), ScheduleID: sch.ID, Status: RunQueued, Trigger: TriggerSchedule, StartedAt: now}
					errs[i] = s.StartResealRun(ctx, run, &due, &next)
				})
			}
			wg.Wait()
			started := 0
			for _, err := range errs {
				switch {
				case err == nil:
					started++
				case !errors.Is(err, ErrRunActive) && !errors.Is(err, ErrScheduleChanged):
					t.Fatalf("start: %v", err)
				}
			}
			if started != 1 {
				t.Fatalf("%d runs started", started)
			}
			got, _, _ := s.ResealSchedule(ctx, sch.ID)
			if got.NextRunAt == nil || !got.NextRunAt.Equal(next) || got.ActiveRunID == "" {
				t.Fatalf("schedule = %+v", got)
			}
			// Run now while one is active
			manual := ResealRun{ID: ulid.Make().String(), ScheduleID: sch.ID, Status: RunQueued, Trigger: TriggerManual, StartedAt: now}
			if err := s.StartResealRun(ctx, manual, nil, nil); !errors.Is(err, ErrRunActive) {
				t.Fatalf("run now while active: %v", err)
			}
			// a due run whose next run moved does not start
			if _, ok, _ := s.CancelResealRun(ctx, got.ActiveRunID, "alice", now); !ok {
				t.Fatal("cancel")
			}
			late := ResealRun{ID: ulid.Make().String(), ScheduleID: sch.ID, Status: RunQueued, StartedAt: now}
			if err := s.StartResealRun(ctx, late, &due, &next); !errors.Is(err, ErrScheduleChanged) {
				t.Fatalf("start with a moved next run: %v", err)
			}
			if err := s.StartResealRun(ctx, manual, nil, nil); err != nil {
				t.Fatalf("run now after cancel: %v", err)
			}
			if err := s.StartResealRun(ctx, ResealRun{ID: ulid.Make().String(), ScheduleID: "missing"}, nil, nil); !errors.Is(err, ErrScheduleChanged) {
				t.Fatalf("start of a missing schedule: %v", err)
			}
		})
	}
}

func TestStore_ResealRuns(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			sch := ResealSchedule{ID: ulid.Make().String(), Name: "n", Orgs: []string{"example-org"}, IntervalDays: 1, CreatedAt: now}
			if err := s.CreateResealSchedule(ctx, sch, 1000); err != nil {
				t.Fatal(err)
			}
			run := ResealRun{
				ID: ulid.Make().String(), ScheduleID: sch.ID, ScheduleName: "n", CreatedBy: "alice", CreatedByID: 1001,
				Orgs: []string{"example-org"}, Trigger: TriggerManual, RequestedBy: "bob", Status: RunQueued, StartedAt: now,
			}
			if err := s.StartResealRun(ctx, run, nil, nil); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.ResealRun(ctx, run.ID)
			if err != nil || !ok || !reflect.DeepEqual(got, run) {
				t.Fatalf("ResealRun = %+v, %v, %v", got, ok, err)
			}

			// one tick at a time
			until := now.Add(2 * time.Minute)
			leased, ok, err := s.LeaseResealRun(ctx, run.ID, until, now)
			if err != nil || !ok || leased.LeaseUntil != until.UnixMilli() {
				t.Fatalf("lease = %+v, %v, %v", leased, ok, err)
			}
			if _, ok, err := s.LeaseResealRun(ctx, run.ID, until.Add(time.Minute), now.Add(time.Minute)); err != nil || ok {
				t.Fatalf("a second lease: %v %v", ok, err)
			}
			// it saves while it holds the lease, keeping or giving it up
			leased.Status, leased.Discovered, leased.Total, leased.InFlight = RunRunning, true, 3, []string{"a/b"}
			leased.Values = ResealCounts{Resealed: 2}
			if ok, err := s.SaveResealRun(ctx, leased, until.UnixMilli()); err != nil || !ok {
				t.Fatalf("save: %v %v", ok, err)
			}
			if ok, err := s.SaveResealRun(ctx, leased, until.Add(time.Second).UnixMilli()); err != nil || ok {
				t.Fatalf("save with another lease: %v %v", ok, err)
			}
			leased.LeaseUntil = 0
			if ok, err := s.SaveResealRun(ctx, leased, until.UnixMilli()); err != nil || !ok {
				t.Fatalf("give up the lease: %v %v", ok, err)
			}
			// a lapsed lease is taken over
			if _, ok, _ := s.LeaseResealRun(ctx, run.ID, until, now); !ok {
				t.Fatal("lease after giving it up")
			}
			again, ok, err := s.LeaseResealRun(ctx, run.ID, until.Add(5*time.Minute), until)
			if err != nil || !ok || again.Total != 3 || !slices.Equal(again.InFlight, []string{"a/b"}) || again.Values.Resealed != 2 {
				t.Fatalf("lease after it lapsed = %+v, %v, %v", again, ok, err)
			}

			// cancelled meanwhile: the tick's save is refused, and the
			// schedule has no active run
			cancelled, ok, err := s.CancelResealRun(ctx, run.ID, "alice", now)
			if err != nil || !ok || cancelled.Status != RunCancelled || cancelled.CancelledBy != "alice" || cancelled.FinishedAt == nil {
				t.Fatalf("cancel = %+v, %v, %v", cancelled, ok, err)
			}
			if ok, err := s.SaveResealRun(ctx, again, again.LeaseUntil); err != nil || ok {
				t.Fatalf("save after cancel: %v %v", ok, err)
			}
			if _, ok, _ := s.CancelResealRun(ctx, run.ID, "alice", now); ok {
				t.Fatal("cancelled twice")
			}
			if got, _, _ := s.ResealSchedule(ctx, sch.ID); got.ActiveRunID != "" || got.LastRunID != run.ID {
				t.Fatalf("schedule after cancel = %+v", got)
			}

			// a run that finishes gives up its schedule's active run
			second := ResealRun{ID: ulid.Make().String(), ScheduleID: sch.ID, Status: RunQueued, StartedAt: now}
			if err := s.StartResealRun(ctx, second, nil, nil); err != nil {
				t.Fatal(err)
			}
			second.Status, second.FinishedAt = RunSucceeded, ptr(now)
			if ok, err := s.SaveResealRun(ctx, second, 0); err != nil || !ok {
				t.Fatalf("finish: %v %v", ok, err)
			}
			if got, _, _ := s.ResealSchedule(ctx, sch.ID); got.ActiveRunID != "" || got.LastRunID != second.ID {
				t.Fatalf("schedule after finish = %+v", got)
			}
			if _, ok, _ := s.LeaseResealRun(ctx, second.ID, until, now); ok {
				t.Fatal("a finished run was leased")
			}

			// newest first, of the schedule
			runs, err := s.ResealRuns(ctx, sch.ID, 10)
			if err != nil || len(runs) != 2 || runs[0].ID != second.ID || runs[1].ID != run.ID {
				t.Fatalf("ResealRuns = %+v, %v", runs, err)
			}
			if runs, _ := s.ResealRuns(ctx, sch.ID, 1); len(runs) != 1 || runs[0].ID != second.ID {
				t.Fatalf("ResealRuns limited = %+v", runs)
			}
			if runs, _ := s.ResealRuns(ctx, "other", 10); len(runs) != 0 {
				t.Fatalf("runs of another schedule = %+v", runs)
			}
		})
	}
}

func TestStore_ResealRunRepos(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			run := ulid.Make().String()
			var repos []ResealRunRepo
			for _, key := range []string{"example-org/c", "example-org/a", "other/b"} {
				repos = append(repos, ResealRunRepo{RunID: run, Key: key, Repo: key, Status: RepoPending, UpdatedAt: now})
			}
			if err := s.PutResealRunRepos(ctx, repos); err != nil {
				t.Fatal(err)
			}
			done := repos[0]
			done.Status, done.Files, done.Values = RepoOpened, 2, ResealCounts{Resealed: 3, Failed: 1}
			done.PullRequest = &ResealRunPull{Number: 7, URL: "https://github.example.com/pull/7"}
			done.Failures = []ResealFailure{{Path: "p", Key: "k", Document: 1, Error: "no key opens it"}}
			done.FromKeys = []string{"SHA256:old"}
			if err := s.PutResealRunRepos(ctx, []ResealRunRepo{done}); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.ResealRunRepo(ctx, run, "example-org/c")
			if err != nil || !ok || !reflect.DeepEqual(got, done) || !got.Done() {
				t.Fatalf("ResealRunRepo = %+v, %v, %v", got, ok, err)
			}
			all, err := s.ResealRunRepos(ctx, run)
			if err != nil || len(all) != 3 || all[0].Key != "example-org/a" || all[2].Key != "other/b" {
				t.Fatalf("ResealRunRepos = %+v, %v", all, err)
			}
			next, err := s.NextResealRunRepos(ctx, run, "example-org/a", 1)
			if err != nil || len(next) != 1 || next[0].Key != "example-org/c" {
				t.Fatalf("next after a = %+v, %v", next, err)
			}
			if next, _ := s.NextResealRunRepos(ctx, run, "", 2); len(next) != 2 || next[0].Key != "example-org/a" {
				t.Fatalf("first two = %+v", next)
			}
			if next, _ := s.NextResealRunRepos(ctx, run, "other/b", 5); len(next) != 0 {
				t.Fatalf("after the last = %+v", next)
			}

			// work and batches stay out of the repositories' listing
			w := ResealWork{
				RunID: run, Key: "example-org/a", Owner: "example-org", Name: "a", Branch: "main", Commit: "abc",
				Candidates: []ResealFile{{Path: "x-sealed.yaml", SHA: "s1", Mode: "100644"}}, Next: 1,
				Files:     []ResealFile{{Path: "x-sealed.yaml", SHA: "s1", Mode: "100644"}},
				Commands:  []ResealCommand{{ID: "cmd-1", AgentID: "use1-blue", Items: 2, ExpiresAt: now}},
				UpdatedAt: now,
			}
			if err := s.PutResealWork(ctx, w); err != nil {
				t.Fatal(err)
			}
			if got, ok, err := s.ResealWork(ctx, run, "example-org/a"); err != nil || !ok || !reflect.DeepEqual(got, w) {
				t.Fatalf("ResealWork = %+v, %v, %v", got, ok, err)
			}
			b := ResealBatch{RunID: run, RepoKey: "example-org/a", CommandID: "cmd-1", Status: CommandSucceeded,
				Items: []ResealBatchItem{{ID: "0/0/k", Status: "resealed", Ciphertext: "AgB", From: "SHA256:old"}, {ID: "0/1/k", Status: "current"}}}
			if ok, err := s.PutResealBatch(ctx, b); err != nil || !ok {
				t.Fatalf("put batch: %v %v", ok, err)
			}
			if ok, err := s.PutResealBatch(ctx, b); err != nil || ok {
				t.Fatalf("put batch again: %v %v", ok, err)
			}
			other := ResealBatch{RunID: run, RepoKey: "example-org/c", CommandID: "cmd-2", Status: CommandFailed, Error: "shut down"}
			if ok, err := s.PutResealBatch(ctx, other); err != nil || !ok {
				t.Fatalf("put another: %v %v", ok, err)
			}
			if ids, err := s.ResealBatchesDone(ctx, run, "example-org/a"); err != nil || !slices.Equal(ids, []string{"cmd-1"}) {
				t.Fatalf("ResealBatchesDone = %v, %v", ids, err)
			}
			if got, ok, err := s.ResealBatch(ctx, run, "example-org/a", "cmd-1"); err != nil || !ok || !reflect.DeepEqual(got, b) {
				t.Fatalf("ResealBatch = %+v, %v, %v", got, ok, err)
			}
			if all, _ := s.ResealRunRepos(ctx, run); len(all) != 3 {
				t.Fatalf("repositories after work and batches = %+v", all)
			}
		})
	}
}
