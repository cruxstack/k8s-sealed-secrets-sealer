package store

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// unique returns a name no other test run uses, so tests share a table.
func unique(prefix, name string) string {
	return prefix + "-" + name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// A command with an external payload keeps it out of the agent's commands,
// which polls read often, and hands it out on its own.
func TestStore_ExternalPayload(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			agent := unique("use1-blue-external", name)
			payload := `{"env_key":"SHA256:a","items":[{"id":"0/k","namespace":"apps","name":"billing","scope":"strict","ciphertext":"` +
				strings.Repeat("A", 100<<10) + `"}]}`
			c := CommandRecord{
				AgentID: agent, ID: ulid.Make().String(), Type: protocol.CommandReseal, Status: CommandQueued,
				CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Payload: payload, ExternalPayload: true,
				SessionID: "SES", ResealID: "01J00000000000000000000RSL", RunID: "RUN", RunRepo: "example-org/apps",
			}
			if err := s.PutCommand(ctx, c); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.Command(ctx, agent, c.ID)
			if err != nil || !ok || got.Payload != "" || got.PayloadBytes != len(payload) || !got.ExternalPayload ||
				got.ResealID != c.ResealID || got.RunID != "RUN" || got.RunRepo != "example-org/apps" {
				t.Fatalf("Command = %+v, %v, %v", got, ok, err)
			}
			list, err := s.CommandsSince(ctx, agent, now.Add(-time.Hour))
			if err != nil || len(list) != 1 || list[0].Payload != "" {
				t.Fatalf("CommandsSince = %+v, %v", list, err)
			}
			if _, err := got.Protocol(); err == nil {
				t.Fatal("a command whose payload was not read was prepared")
			}
			p, ok, err := s.CommandPayload(ctx, c.ID)
			if err != nil || !ok || p != payload {
				t.Fatalf("CommandPayload = %d bytes, %v, %v", len(p), ok, err)
			}
			got.Payload = p
			if cmd, err := got.Protocol(); err != nil || string(cmd.Payload) != payload {
				t.Fatalf("Protocol = %v", err)
			}
			if _, ok, err := s.CommandPayload(ctx, "01J0000000000000000000000Z"); err != nil || ok {
				t.Fatalf("unknown payload: %v %v", ok, err)
			}
		})
	}
}

// A reseal holds a place for each change it will make, all at once or none.
func TestStore_ReserveChanges(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			session := unique("SES-reserve-many", name)
			until := now.Add(time.Minute)
			if err := s.ReserveChange(ctx, session, "a", "seal-a", []string{"x"}, 4, until, now); err != nil {
				t.Fatal(err)
			}
			// x exists and a is held: three more would make five
			three := map[string]string{"r1": "cmd-1", "r2": "cmd-1", "r3": "cmd-2"}
			if err := s.ReserveChanges(ctx, session, three, []string{"x"}, 4, until, now); !errors.Is(err, ErrTooManyChanges) {
				t.Fatalf("reserve past the cap: %v", err)
			}
			two := map[string]string{"r1": "cmd-1", "r2": "cmd-2"}
			if err := s.ReserveChanges(ctx, session, two, []string{"x"}, 4, until, now); err != nil {
				t.Fatalf("reserve two: %v", err)
			}
			if err := s.ReserveChange(ctx, session, "b", "seal-b", []string{"x"}, 4, until, now); !errors.Is(err, ErrTooManyChanges) {
				t.Fatalf("none of the first three were held: %v", err)
			}
			// a reseal's command gives up its places together
			if err := s.ReleaseChanges(ctx, session, map[string]string{"r1": "cmd-1", "r2": "cmd-1"}, now); err != nil {
				t.Fatal(err)
			}
			// r2 is held for cmd-2, not cmd-1: one place is free
			if err := s.ReserveChange(ctx, session, "b", "seal-b", []string{"x"}, 4, until, now); err != nil {
				t.Fatalf("reserve after release: %v", err)
			}
			if err := s.ReserveChange(ctx, session, "c", "seal-c", []string{"x"}, 4, until, now); !errors.Is(err, ErrTooManyChanges) {
				t.Fatalf("r2 is still held: %v", err)
			}
			// nothing new to hold is never refused
			if err := s.ReserveChanges(ctx, session, map[string]string{"x": "seal-x"}, []string{"x"}, 4, until, now); err != nil {
				t.Fatalf("reserve an existing change: %v", err)
			}
		})
	}
}

func TestStore_FileReseals(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			session := unique("SES-reseal", name)
			index := 2
			r := FileReseal{
				SessionID: session, ID: "01J00000000000000000000RSL", Path: "deploy/sealed-secret.yaml", AgentID: "use1-blue",
				EnvKey: "SHA256:env", UserID: 1001, UserLogin: "alice", CreatedAt: now, ExpiresAt: now.Add(8 * time.Hour),
				Documents: []Target{{Index: &index, Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict, Region: "use1"}},
				Commands: []FileResealCommand{
					{ID: "cmd-1", Keys: []string{"a", "b"}, Items: []string{"0/2/a", "0/2/b"}},
					{ID: "cmd-2", Keys: []string{"c"}, Items: []string{"0/2/c"}},
				},
				Total: 5, Pending: 1,
				Failures: []ResealFailure{{Key: "d", Document: 2, Region: "use1", Error: "cluster-wide"}},
			}
			if err := s.PutFileReseal(ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := s.PutFileReseal(ctx, r); err == nil {
				t.Fatal("a file reseal was stored twice")
			}
			got, ok, err := s.FileReseal(ctx, session, r.ID)
			if err != nil || !ok || got.Path != r.Path || !reflect.DeepEqual(got.Documents, r.Documents) ||
				!reflect.DeepEqual(got.Commands, r.Commands) || !reflect.DeepEqual(got.Failures, r.Failures) || len(got.Outcomes) != 0 {
				t.Fatalf("FileReseal = %+v, %v, %v", got, ok, err)
			}

			o := ResealOutcome{
				Status: CommandSucceeded, Counts: ResealCounts{Resealed: 1, Failed: 1}, FinishedAt: now,
				Failures:  []ResealFailure{{Key: "b", Document: 2, Error: "no key opens it"}},
				ChangeIDs: []string{"change-a"},
			}
			if ok, err := s.RecordResealOutcome(ctx, session, r.ID, "cmd-1", o); err != nil || !ok {
				t.Fatalf("record: %v %v", ok, err)
			}
			// once per command
			if ok, err := s.RecordResealOutcome(ctx, session, r.ID, "cmd-1", ResealOutcome{Status: CommandFailed}); err != nil || ok {
				t.Fatalf("record again: %v %v", ok, err)
			}
			failed := ResealOutcome{Status: CommandFailed, Error: "the agent shut down", FinishedAt: now}
			if ok, err := s.RecordResealOutcome(ctx, session, r.ID, "cmd-2", failed); err != nil || !ok {
				t.Fatalf("record the second: %v %v", ok, err)
			}
			if ok, err := s.RecordResealOutcome(ctx, session, "01J00000000000000000000XXX", "cmd-1", o); err != nil || ok {
				t.Fatalf("record for an unknown reseal: %v %v", ok, err)
			}
			got, _, _ = s.FileReseal(ctx, session, r.ID)
			if len(got.Outcomes) != 2 || !reflect.DeepEqual(got.Outcomes["cmd-1"], o) || got.Outcomes["cmd-2"].Error != failed.Error {
				t.Fatalf("outcomes = %+v", got.Outcomes)
			}
			if _, ok, err := s.FileReseal(ctx, "SES-other", r.ID); err != nil || ok {
				t.Fatalf("reseal of another session: %v %v", ok, err)
			}
		})
	}
}

// Changes keep their kind, and listings name the keys a reseal moved values
// off.
func TestStore_ResealChanges(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			session := unique("SES-reseal-change", name)
			c := Change{
				SessionID: session, ID: "r1", Path: "p", Key: "k", CommandID: "01J0000000000000000000000A", AgentID: "a",
				Fingerprint: "SHA256:env", Targets: []Target{{Namespace: "apps", Name: "billing", Scope: "strict"}}, Ciphertexts: []string{"Ag"},
				SealedAt: now, ExpiresAt: now.Add(time.Hour), Kind: ChangeReseal, ResealedFrom: []string{"SHA256:old"},
			}
			if ok, err := s.PutChange(ctx, c); err != nil || !ok {
				t.Fatal(ok, err)
			}
			list, err := s.Changes(ctx, session, false)
			if err != nil || len(list) != 1 || !list[0].Resealed() || !slices.Equal(list[0].ResealedFrom, c.ResealedFrom) {
				t.Fatalf("Changes = %+v, %v", list, err)
			}
		})
	}
}

func TestStore_ResealPullRequests(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			// one table serves every subtest: repositories of their own
			repo := unique("example-org/Apps", name)
			pr := func(repo string, number int, source string) ResealPullRequest {
				return ResealPullRequest{
					Repo: repo, Number: number, URL: "https://github.example.com/pull/" + strconv.Itoa(number), Title: "Reseal",
					Branch: "sealer/dev/reseal-x", State: PullOpen, Source: source, RequestedBy: "alice",
					OpenedAt: now, CheckedAt: now, Values: 3, Files: 1, FromKeys: []string{"SHA256:old"},
				}
			}
			for _, p := range []ResealPullRequest{pr(repo, 10, SourceSchedule), pr(repo, 9, SourceSession), pr(repo+"-other", 1, SourceSchedule)} {
				if err := s.PutResealPullRequest(ctx, p); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.PutResealPullRequest(ctx, ResealPullRequest{Repo: repo}); err == nil {
				t.Fatal("a pull request without a number was stored")
			}
			key := strings.ToLower(repo)
			open, err := s.ResealPullRequests(ctx, true, key)
			if err != nil || len(open) != 2 || open[0].Number != 9 || open[1].Number != 10 || open[1].Repo != repo ||
				!slices.Equal(open[1].FromKeys, []string{"SHA256:old"}) {
				t.Fatalf("open = %+v, %v", open, err)
			}

			// checked, still open
			checked := open[1]
			checked.CheckedAt = now.Add(time.Minute)
			if ok, err := s.UpdateResealPullRequest(ctx, checked); err != nil || !ok {
				t.Fatalf("update: %v %v", ok, err)
			}
			// merged: among the ended ones
			merged := checked
			merged.State, merged.MergedAt = PullMerged, ptr(now.Add(2*time.Minute))
			if ok, err := s.UpdateResealPullRequest(ctx, merged); err != nil || !ok {
				t.Fatalf("merge: %v %v", ok, err)
			}
			// a tick that read it open before does not record it again
			if ok, err := s.UpdateResealPullRequest(ctx, merged); err != nil || ok {
				t.Fatalf("merge again: %v %v", ok, err)
			}
			if ok, err := s.UpdateResealPullRequest(ctx, checked); err != nil || ok {
				t.Fatalf("an update of a merged one: %v %v", ok, err)
			}
			open, _ = s.ResealPullRequests(ctx, true, key)
			if len(open) != 1 || open[0].Number != 9 {
				t.Fatalf("open after the merge = %+v", open)
			}
			done, err := s.ResealPullRequests(ctx, false, key)
			if err != nil || len(done) != 1 || done[0].State != PullMerged || done[0].MergedAt == nil || !done[0].CheckedAt.Equal(checked.CheckedAt) {
				t.Fatalf("ended = %+v, %v", done, err)
			}
			all, err := s.ResealPullRequests(ctx, true, "")
			if err != nil || !slices.ContainsFunc(all, func(p ResealPullRequest) bool { return p.Repo == repo+"-other" }) {
				t.Fatalf("every open one = %+v, %v", all, err)
			}
		})
	}
}
