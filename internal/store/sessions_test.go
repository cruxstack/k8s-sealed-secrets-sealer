package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

func TestStore_CommandSecretIsLeasedOnce(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			agent := "use1-blue-secret-" + name
			c := CommandRecord{
				AgentID: agent, ID: "01J0000000000000000000000S", Type: protocol.CommandSeal, Status: CommandQueued,
				CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute),
				Payload:   `{"key":"k","fingerprint":"SHA256:a","targets":[]}`,
				Secret:    `{"key_id":"transit","wrapped_key":"d2s=","nonce":"bg==","ciphertext":"Yw==","context":{"env":"dev"}}`,
				SessionID: "01J00000000000000000000SES",
			}
			if err := s.PutCommand(ctx, c); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.Command(ctx, agent, c.ID)
			if err != nil || !ok || got.Secret != c.Secret || got.SessionID != c.SessionID {
				t.Fatalf("Command = %+v, %v, %v", got, ok, err)
			}
			// the secret goes out as the payload's value
			cmd, err := got.Protocol()
			if err != nil {
				t.Fatal(err)
			}
			var p protocol.SealPayload
			if err := json.Unmarshal(cmd.Payload, &p); err != nil || p.Key != "k" || p.Value == nil || p.Value.KeyID != "transit" {
				t.Fatalf("payload = %s, %v", cmd.Payload, err)
			}
			// and leasing removes it from the store
			if ok, err := s.LeaseCommand(ctx, agent, c.ID, now); err != nil || !ok {
				t.Fatalf("lease: ok=%v err=%v", ok, err)
			}
			got, _, _ = s.Command(ctx, agent, c.ID)
			if got.Secret != "" || got.Status != CommandLeased {
				t.Fatalf("after lease: %+v", got)
			}
			if _, ok, err := s.Command(ctx, agent, "01J0000000000000000000000Z"); err != nil || ok {
				t.Fatalf("unknown command: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestStore_Sessions(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			user := time.Now().UnixNano() // unique per run against a shared table
			session := func(id, repo string, expires time.Time) Session {
				return Session{
					ID: id, UserID: user, UserLogin: "alice", Owner: "Example-Org", Repo: repo,
					Branch: "main", Commit: "abc", CreatedAt: now, UsedAt: now, ExpiresAt: expires, EndsAt: now.Add(8 * time.Hour),
				}
			}
			apps := session("S1", "apps", now.Add(time.Hour))
			got, created, err := s.CreateSession(ctx, apps, 2, now)
			if err != nil || !created || got.ID != "S1" {
				t.Fatalf("create = %+v, %v, %v", got, created, err)
			}
			// a second session for the same repository returns the first
			got, created, err = s.CreateSession(ctx, session("S2", "APPS", now.Add(time.Hour)), 2, now)
			if err != nil || created || got.ID != "S1" || got.Commit != "abc" || !got.EndsAt.Equal(apps.EndsAt) {
				t.Fatalf("create again = %+v, %v, %v", got, created, err)
			}
			if _, created, err := s.CreateSession(ctx, session("S3", "platform", now.Add(time.Hour)), 2, now); err != nil || !created {
				t.Fatalf("create platform: %v %v", created, err)
			}
			// the cap counts live sessions
			if _, _, err := s.CreateSession(ctx, session("S4", "infra", now.Add(time.Hour)), 2, now); !errors.Is(err, ErrTooManySessions) {
				t.Fatalf("over the cap: %v", err)
			}
			list, err := s.Sessions(ctx, user, now)
			if err != nil || len(list) != 2 {
				t.Fatalf("Sessions = %+v, %v", list, err)
			}
			if other, err := s.Sessions(ctx, user+1, now); err != nil || len(other) != 0 {
				t.Fatalf("another user's sessions = %+v, %v", other, err)
			}

			key := RepoKey("example-org", "apps")
			if got, ok, err := s.Session(ctx, user, key, now); err != nil || !ok || got.ID != "S1" {
				t.Fatalf("Session = %+v, %v, %v", got, ok, err)
			}
			// touching moves the expiry on, but only for the same session
			later := now.Add(30 * time.Minute)
			if ok, err := s.TouchSession(ctx, user, key, "S2", later.Add(time.Hour), later); err != nil || ok {
				t.Fatalf("touch another session: %v %v", ok, err)
			}
			if ok, err := s.TouchSession(ctx, user, key, "S1", later.Add(time.Hour), later); err != nil || !ok {
				t.Fatalf("touch: %v %v", ok, err)
			}
			if got, ok, _ := s.Session(ctx, user, key, now.Add(time.Hour+time.Minute)); !ok || !got.UsedAt.Equal(later) {
				t.Fatalf("after touch = %+v, %v", got, ok)
			}
			// an expired session is gone, cannot be touched, and is replaced
			expiredAt := later.Add(time.Hour)
			if _, ok, _ := s.Session(ctx, user, key, expiredAt); ok {
				t.Fatal("expired session is still returned")
			}
			if ok, err := s.TouchSession(ctx, user, key, "S1", expiredAt.Add(time.Hour), expiredAt); err != nil || ok {
				t.Fatalf("touch expired: %v %v", ok, err)
			}
			got, created, err = s.CreateSession(ctx, session("S5", "apps", expiredAt.Add(time.Hour)), 2, expiredAt)
			if err != nil || !created || got.ID != "S5" {
				t.Fatalf("replace expired = %+v, %v, %v", got, created, err)
			}

			// deleting needs the current session's ID
			if ok, err := s.DeleteSession(ctx, user, key, "S1"); err != nil || ok {
				t.Fatalf("delete a replaced session: %v %v", ok, err)
			}
			if ok, err := s.DeleteSession(ctx, user, key, "S5"); err != nil || !ok {
				t.Fatalf("delete: %v %v", ok, err)
			}
			if _, ok, _ := s.Session(ctx, user, key, expiredAt); ok {
				t.Fatal("deleted session is still returned")
			}
		})
	}
}

func TestStore_SessionCapHoldsUnderConcurrency(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			user := time.Now().UnixNano()
			const limit, tries = 3, 8
			var created, refused atomic.Int32
			var wg sync.WaitGroup
			for i := range tries {
				wg.Go(func() {
					sess := Session{
						ID: "S" + strconv.Itoa(i), UserID: user, UserLogin: "alice", Owner: "example-org", Repo: "repo-" + strconv.Itoa(i),
						Branch: "main", Commit: "abc", CreatedAt: now, UsedAt: now, ExpiresAt: now.Add(time.Hour), EndsAt: now.Add(8 * time.Hour),
					}
					_, ok, err := s.CreateSession(ctx, sess, limit, now)
					switch {
					case errors.Is(err, ErrTooManySessions):
						refused.Add(1)
					case err != nil:
						t.Errorf("create %d: %v", i, err)
					case ok:
						created.Add(1)
					}
				})
			}
			wg.Wait()
			live, err := s.Sessions(ctx, user, now)
			if err != nil {
				t.Fatal(err)
			}
			if created.Load() != limit || refused.Load() != tries-limit || len(live) != limit {
				t.Fatalf("created %d, refused %d, live %d; want %d created", created.Load(), refused.Load(), len(live), limit)
			}
		})
	}
}

func TestStore_ReserveChange(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			session := "SES-reserve-" + name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
			existing := []string{"x"}
			// a seal holds its place for three minutes
			reserve := func(id, seal string, at time.Time) error {
				return s.ReserveChange(ctx, session, id, seal, existing, 3, at.Add(3*time.Minute), at)
			}
			// one change exists; two seals of new changes in flight fill
			// the session
			for _, id := range []string{"a", "b"} {
				if err := reserve(id, "seal-"+id, now); err != nil {
					t.Fatalf("reserve %s: %v", id, err)
				}
			}
			if err := reserve("c", "seal-c", now); !errors.Is(err, ErrTooManyChanges) {
				t.Fatalf("reserve past the cap: %v", err)
			}
			// sealing a change again, existing or in flight, takes no
			// other place
			if err := reserve("x", "seal-x", now); err != nil {
				t.Fatalf("reserve an existing change: %v", err)
			}
			if err := reserve("a", "seal-a2", now.Add(2*time.Minute)); err != nil {
				t.Fatalf("reserve a again: %v", err)
			}
			// b's seal has had its time and its place lapses; a's second
			// seal still holds one
			later := now.Add(3*time.Minute + time.Second)
			if err := reserve("c", "seal-c", later); err != nil {
				t.Fatalf("reserve after b's place lapsed: %v", err)
			}
			if err := reserve("d", "seal-d", later); !errors.Is(err, ErrTooManyChanges) {
				t.Fatalf("reserve past the cap again: %v", err)
			}
			if err := s.ReserveChange(ctx, "SES-other-"+session, "d", "seal-d", nil, 3, now.Add(time.Minute), now); err != nil {
				t.Fatalf("reserve in another session: %v", err)
			}
		})
	}
}

// A seal gives its place up once its change is stored (the change then
// counts itself) or it failed, and only its own: another seal of the same
// change keeps holding one.
func TestStore_ReleaseChange(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			session := "SES-release-" + name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
			reserve := func(id, seal string) error {
				return s.ReserveChange(ctx, session, id, seal, nil, 2, now.Add(3*time.Minute), now)
			}
			for _, place := range [][2]string{{"a", "seal-a1"}, {"a", "seal-a2"}, {"b", "seal-b"}} {
				if err := reserve(place[0], place[1]); err != nil {
					t.Fatalf("reserve %v: %v", place, err)
				}
			}
			if err := reserve("c", "seal-c"); !errors.Is(err, ErrTooManyChanges) {
				t.Fatalf("reserve past the cap: %v", err)
			}
			// b's seal is done and its change removed: its place is free
			if err := s.ReleaseChange(ctx, session, "b", "seal-b", now); err != nil {
				t.Fatal(err)
			}
			if err := reserve("c", "seal-c"); err != nil {
				t.Fatalf("reserve after b's seal released its place: %v", err)
			}
			if err := reserve("d", "seal-d"); !errors.Is(err, ErrTooManyChanges) {
				t.Fatalf("reserve past the cap again: %v", err)
			}
			// one of a's seals is done; the other still holds a's place
			if err := s.ReleaseChange(ctx, session, "a", "seal-a1", now); err != nil {
				t.Fatal(err)
			}
			if err := reserve("d", "seal-d"); !errors.Is(err, ErrTooManyChanges) {
				t.Fatalf("reserve while a's second seal runs: %v", err)
			}
			// releasing what is not held changes nothing
			if err := s.ReleaseChange(ctx, session, "z", "seal-z", now); err != nil {
				t.Fatal(err)
			}
			if err := s.ReleaseChange(ctx, "SES-none-"+session, "a", "seal-a2", now); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStore_ChangeCapHoldsUnderConcurrency(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			session := "SES-race-" + name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
			const limit, tries = 3, 6
			var reserved, refused atomic.Int32
			var wg sync.WaitGroup
			for i := range tries {
				wg.Go(func() {
					err := s.ReserveChange(ctx, session, "c"+strconv.Itoa(i), "seal-"+strconv.Itoa(i), nil, limit, now.Add(time.Minute), now)
					switch {
					case errors.Is(err, ErrTooManyChanges):
						refused.Add(1)
					case err != nil:
						t.Errorf("reserve %d: %v", i, err)
					default:
						reserved.Add(1)
					}
				})
			}
			wg.Wait()
			if reserved.Load() != limit || refused.Load() != tries-limit {
				t.Fatalf("reserved %d, refused %d; want %d reserved", reserved.Load(), refused.Load(), limit)
			}
		})
	}
}

func TestStore_SessionLock(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			user := time.Now().UnixNano()
			sess := Session{
				ID: "S1", UserID: user, UserLogin: "alice", Owner: "example-org", Repo: "apps", Branch: "main", Commit: "abc",
				CreatedAt: now, UsedAt: now, ExpiresAt: now.Add(time.Hour), EndsAt: now.Add(8 * time.Hour),
			}
			if _, _, err := s.CreateSession(ctx, sess, 10, now); err != nil {
				t.Fatal(err)
			}
			key := RepoKey("example-org", "apps")
			if ok, err := s.LockSession(ctx, user, key, "S2", now.Add(time.Minute), now); err != nil || ok {
				t.Fatalf("lock of another session: %v, %v", ok, err)
			}
			if ok, err := s.LockSession(ctx, user, key, "S1", now.Add(time.Minute), now); err != nil || !ok {
				t.Fatalf("lock: %v, %v", ok, err)
			}
			if got, _, _ := s.Session(ctx, user, key, now); !got.Locked(now) || got.Locked(now.Add(time.Minute)) {
				t.Fatalf("locked session = %+v", got)
			}
			if ok, err := s.LockSession(ctx, user, key, "S1", now.Add(time.Minute), now); err != nil || ok {
				t.Fatalf("second lock: %v, %v", ok, err)
			}
			// a locked session cannot be used
			if ok, err := s.TouchSession(ctx, user, key, "S1", now.Add(time.Hour), now); !errors.Is(err, ErrSessionBusy) || ok {
				t.Fatalf("touch while locked: %v, %v", ok, err)
			}
			if ok, err := s.TouchSession(ctx, user, key, "S2", now.Add(time.Hour), now); err != nil || ok {
				t.Fatalf("touch of another session: %v, %v", ok, err)
			}
			if err := s.UnlockSession(ctx, user, key, "S1"); err != nil {
				t.Fatal(err)
			}
			if ok, err := s.TouchSession(ctx, user, key, "S1", now.Add(time.Hour), now); err != nil || !ok {
				t.Fatalf("touch after unlock: %v, %v", ok, err)
			}
			// a lock lapses at its deadline
			if ok, _ := s.LockSession(ctx, user, key, "S1", now.Add(time.Minute), now); !ok {
				t.Fatal("lock again")
			}
			later := now.Add(2 * time.Minute)
			if ok, err := s.TouchSession(ctx, user, key, "S1", later.Add(time.Hour), later); err != nil || !ok {
				t.Fatalf("touch after the lock lapsed: %v, %v", ok, err)
			}
			if ok, _ := s.LockSession(ctx, user, key, "S1", later.Add(time.Minute), later); !ok {
				t.Fatal("lock after the lock lapsed")
			}
			// a locked session cannot be discarded, nor another one
			if ok, err := s.DiscardSession(ctx, user, key, "S1", later); !errors.Is(err, ErrSessionBusy) || ok {
				t.Fatalf("discard while locked: %v, %v", ok, err)
			}
			if ok, err := s.DiscardSession(ctx, user, key, "S2", later); err != nil || ok {
				t.Fatalf("discard of another session: %v, %v", ok, err)
			}
			// an expired session cannot be locked
			if ok, err := s.LockSession(ctx, user, key, "S1", now.Add(3*time.Hour), now.Add(2*time.Hour)); err != nil || ok {
				t.Fatalf("lock of an expired session: %v, %v", ok, err)
			}
			if err := s.UnlockSession(ctx, user, key, "S1"); err != nil {
				t.Fatal(err)
			}
			if ok, err := s.DiscardSession(ctx, user, key, "S1", later); err != nil || !ok {
				t.Fatalf("discard: %v, %v", ok, err)
			}
			if _, ok, _ := s.Session(ctx, user, key, later); ok {
				t.Fatal("session still there after discard")
			}
			if err := s.UnlockSession(ctx, user, "example-org/none", "S9"); err != nil {
				t.Fatalf("unlock of a missing session: %v", err)
			}
		})
	}
}

func TestStore_SealsAndChanges(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			session := "SES-" + name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
			user := time.Now().UnixNano()
			repoKey := RepoKey("example-org", "apps")
			if _, _, err := s.CreateSession(ctx, Session{
				ID: session, UserID: user, UserLogin: "alice", Owner: "example-org", Repo: "apps", Branch: "main", Commit: "abc",
				CreatedAt: now, UsedAt: now, ExpiresAt: now.Add(time.Hour), EndsAt: now.Add(8 * time.Hour),
			}, 10, now); err != nil {
				t.Fatal(err)
			}
			index := 3
			targets := []Target{{Index: &index, Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict, Region: "use1"}}

			seal := Seal{
				SessionID: session, CommandID: "01J0000000000000000000000A", AgentID: "use1-blue",
				Path: "deploy/sealed-secret.yaml", Key: "token", Fingerprint: "SHA256:a", Targets: targets,
				UserID: 1001, UserLogin: "alice", CreatedAt: now, ExpiresAt: now.Add(8 * time.Hour),
			}
			if err := s.PutSeal(ctx, seal); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.Seal(ctx, session, seal.CommandID)
			if err != nil || !ok || got.AgentID != "use1-blue" || got.Path != seal.Path || !reflect.DeepEqual(got.Targets, targets) {
				t.Fatalf("Seal = %+v, %v, %v", got, ok, err)
			}
			if _, ok, err := s.Seal(ctx, "other-session", seal.CommandID); err != nil || ok {
				t.Fatalf("seal in another session: %v %v", ok, err)
			}

			change := func(cmd, ciphertext string) Change {
				return Change{
					SessionID: session, ID: "c1", Path: seal.Path, Key: "token", CommandID: cmd, AgentID: "use1-blue",
					Fingerprint: "SHA256:a", Targets: targets, Ciphertexts: []string{ciphertext},
					UserID: 1001, UserLogin: "alice", SealedAt: now, ExpiresAt: now.Add(8 * time.Hour),
				}
			}
			if ok, err := s.PutChange(ctx, change("01J0000000000000000000000B", "Ag-b")); err != nil || !ok {
				t.Fatalf("put change: %v %v", ok, err)
			}
			// an older seal finishing late does not replace a newer one
			if ok, err := s.PutChange(ctx, change("01J0000000000000000000000A", "Ag-a")); err != nil || ok {
				t.Fatalf("put older change: %v %v", ok, err)
			}
			if ok, err := s.PutChange(ctx, change("01J0000000000000000000000C", "Ag-c")); err != nil || !ok {
				t.Fatalf("put newer change: %v %v", ok, err)
			}
			second := change("01J0000000000000000000000D", "Ag-d")
			second.ID, second.Key = "c2", "password"
			if ok, err := s.PutChange(ctx, second); err != nil || !ok {
				t.Fatalf("put second change: %v %v", ok, err)
			}

			// listings leave the ciphertexts out
			list, err := s.Changes(ctx, session, false)
			if err != nil || len(list) != 2 || list[0].ID != "c1" || list[0].CommandID != "01J0000000000000000000000C" {
				t.Fatalf("Changes = %+v, %v", list, err)
			}
			if list[0].Ciphertexts != nil || list[0].Path != seal.Path || !reflect.DeepEqual(list[0].Targets, targets) {
				t.Fatalf("listed change = %+v", list[0])
			}
			full, err := s.Changes(ctx, session, true)
			if err != nil || !slices.Equal(full[0].Ciphertexts, []string{"Ag-c"}) {
				t.Fatalf("Changes with ciphertexts = %+v, %v", full, err)
			}

			// pruning leaves a change a newer seal replaced since
			if ok, err := s.PruneChange(ctx, session, "c1", "01J0000000000000000000000B"); err != nil || ok {
				t.Fatalf("prune of a replaced change: %v %v", ok, err)
			}
			if list, _ := s.Changes(ctx, session, false); len(list) != 2 {
				t.Fatalf("after pruning a replaced change = %+v", list)
			}
			if ok, err := s.PruneChange(ctx, session, "c2", "01J0000000000000000000000D"); err != nil || !ok {
				t.Fatalf("prune: %v %v", ok, err)
			}

			// changes are not removed while a pull request is being opened
			if ok, _ := s.LockSession(ctx, user, repoKey, session, now.Add(time.Minute), now); !ok {
				t.Fatal("lock")
			}
			if ok, err := s.RemoveChange(ctx, user, repoKey, session, "c1", now); !errors.Is(err, ErrSessionBusy) || ok {
				t.Fatalf("remove while locked: %v %v", ok, err)
			}
			if err := s.UnlockSession(ctx, user, repoKey, session); err != nil {
				t.Fatal(err)
			}
			if ok, err := s.RemoveChange(ctx, user, repoKey, "SES-other", "c1", now); err != nil || ok {
				t.Fatalf("remove from another session: %v %v", ok, err)
			}
			if ok, err := s.RemoveChange(ctx, user, repoKey, session, "c1", now); err != nil || !ok {
				t.Fatalf("remove change: %v %v", ok, err)
			}
			if ok, err := s.RemoveChange(ctx, user, repoKey, session, "c1", now); err != nil || ok {
				t.Fatalf("remove change again: %v %v", ok, err)
			}
			if list, _ := s.Changes(ctx, session, false); len(list) != 0 {
				t.Fatalf("after remove = %+v", list)
			}
		})
	}
}
