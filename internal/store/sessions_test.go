package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
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

func TestStore_SealsAndChanges(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			session := "SES-" + name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
			targets := []Target{{Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict, Region: "use1"}}

			seal := Seal{
				SessionID: session, CommandID: "01J0000000000000000000000A", AgentID: "use1-blue",
				Path: "deploy/sealed-secret.yaml", Key: "token", Fingerprint: "SHA256:a", Targets: targets,
				UserID: 1001, UserLogin: "alice", CreatedAt: now, ExpiresAt: now.Add(8 * time.Hour),
			}
			if err := s.PutSeal(ctx, seal); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.Seal(ctx, session, seal.CommandID)
			if err != nil || !ok || got.AgentID != "use1-blue" || got.Path != seal.Path || !slices.Equal(got.Targets, targets) {
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
			if list[0].Ciphertexts != nil || list[0].Path != seal.Path || !slices.Equal(list[0].Targets, targets) {
				t.Fatalf("listed change = %+v", list[0])
			}
			full, err := s.Changes(ctx, session, true)
			if err != nil || !slices.Equal(full[0].Ciphertexts, []string{"Ag-c"}) {
				t.Fatalf("Changes with ciphertexts = %+v, %v", full, err)
			}

			if ok, err := s.DeleteChange(ctx, session, "c1"); err != nil || !ok {
				t.Fatalf("delete change: %v %v", ok, err)
			}
			if ok, err := s.DeleteChange(ctx, session, "c1"); err != nil || ok {
				t.Fatalf("delete change again: %v %v", ok, err)
			}
			if list, _ := s.Changes(ctx, session, false); len(list) != 1 || list[0].ID != "c2" {
				t.Fatalf("after delete = %+v", list)
			}
		})
	}
}
