package store

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// stores returns the stores to test: always the in-memory one, and DynamoDB
// Local when SEALER_TEST_DYNAMODB_ENDPOINT is set (atmos test integration).
func stores(t *testing.T) map[string]Store {
	t.Helper()
	out := map[string]Store{"memory": NewMemory()}
	endpoint := os.Getenv("SEALER_TEST_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		return out
	}
	client := dynamodb.New(dynamodb.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider("local", "local", ""),
	})
	d := NewDynamo(client, "sealer-test-"+time.Now().Format("150405.000000"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := d.EnsureTable(ctx); err != nil {
		t.Fatalf("EnsureTable: %v", err)
	}
	// a second call finds the table and returns
	if err := d.EnsureTable(ctx); err != nil {
		t.Fatalf("EnsureTable again: %v", err)
	}
	out["dynamodb"] = d
	return out
}

func TestStore_AgentStates(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			state := AgentState{
				AgentID:      "use1-blue",
				LastCheckIn:  now,
				AgentVersion: "v1.2.3",
				Protocol:     protocol.Version,
				Capabilities: []string{"seal", "keys"},
				Controller:   protocol.Controller{Namespace: "sealed-secrets", Name: "sealed-secrets-controller", ActiveFingerprint: "SHA256:a"},
				Keys:         []KeyRef{{Fingerprint: "SHA256:a", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}},
				KeysComplete: true,
				KeysReported: 3,
				DroppedUpTo:  ptr(now.Add(-2 * time.Hour)),
				JoinedAt:     ptr(now.Add(-time.Minute)),

				CheckInIntervalSeconds: 60,
				UsageScannedAt:         ptr(now.Add(-time.Second)),
				UsageUnmatched:         2,
			}
			if err := s.PutAgentState(ctx, state); err != nil {
				t.Fatal(err)
			}
			// more IDs than one DynamoDB batch, most of them unknown
			ids := []string{"use1-blue"}
			for i := range 150 {
				ids = append(ids, "missing-"+time.Duration(i).String())
			}
			got, err := s.GetAgentStates(ctx, ids)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d states, want 1", len(got))
			}
			g := got["use1-blue"]
			if !g.LastCheckIn.Equal(now) || g.Controller.ActiveFingerprint != "SHA256:a" || len(g.Keys) != 1 || !g.KeysComplete || g.CheckInIntervalSeconds != 60 {
				t.Fatalf("state round trip: %+v", g)
			}
			if g.KeysReported != 3 || g.DroppedUpTo == nil || !g.DroppedUpTo.Equal(*state.DroppedUpTo) || g.JoinedAt == nil || !g.JoinedAt.Equal(*state.JoinedAt) {
				t.Fatalf("key limit and joining round trip: %+v", g)
			}
			if g.UsageScannedAt == nil || !g.UsageScannedAt.Equal(*state.UsageScannedAt) || g.UsageUnmatched != 2 {
				t.Fatalf("usage marker round trip: %+v", g)
			}
			// states stored before these were recorded read as unknown
			state.AgentID, state.KeysReported, state.DroppedUpTo, state.JoinedAt = "use1-green", 0, nil, nil
			state.UsageScannedAt, state.UsageUnmatched = nil, 0
			if err := s.PutAgentState(ctx, state); err != nil {
				t.Fatal(err)
			}
			got, err = s.GetAgentStates(ctx, []string{"use1-green"})
			if g := got["use1-green"]; err != nil || g.KeysReported != 0 || g.DroppedUpTo != nil || g.JoinedAt != nil || g.UsageScannedAt != nil {
				t.Fatalf("state without them: %+v %v", g, err)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestStore_PutKeyIfAbsent(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			k := KeyRecord{Fingerprint: "SHA256:k", Certificate: "PEM", FirstSeenAgent: "use1-blue", FirstSeenAt: time.Now().UTC()}
			created, err := s.PutKeyIfAbsent(ctx, k)
			if err != nil || !created {
				t.Fatalf("first put: created=%v err=%v", created, err)
			}
			k.FirstSeenAgent = "use2-blue"
			created, err = s.PutKeyIfAbsent(ctx, k)
			if err != nil || created {
				t.Fatalf("second put: created=%v err=%v", created, err)
			}
		})
	}
}

func TestStore_PutReplayIfAbsent(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			key := "sig-" + name + "-" + time.Now().Format("150405.000000")
			first, err := s.PutReplayIfAbsent(ctx, key, time.Now().Add(20*time.Minute))
			if err != nil || !first {
				t.Fatalf("first use: recorded=%v err=%v", first, err)
			}
			again, err := s.PutReplayIfAbsent(ctx, key, time.Now().Add(20*time.Minute))
			if err != nil || again {
				t.Fatalf("second use: recorded=%v err=%v", again, err)
			}
		})
	}
}

func TestStore_Commands(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			agent := "use1-blue-" + name
			first := CommandRecord{AgentID: agent, ID: "01J0000000000000000000000A", Type: protocol.CommandKeysRestore, Status: CommandQueued, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Payload: `{"fingerprints":["SHA256:a"]}`}
			second := first
			second.ID = "01J0000000000000000000000B"
			expired := first
			expired.ID = "01J0000000000000000000000C"
			expired.ExpiresAt = now.Add(-time.Second)
			other := first
			other.AgentID = "use2-blue-" + name
			for _, c := range []CommandRecord{second, first, expired, other} {
				if err := s.PutCommand(ctx, c); err != nil {
					t.Fatal(err)
				}
			}

			got, err := s.Commands(ctx, agent)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 3 || got[0].ID != first.ID || got[1].ID != second.ID {
				t.Fatalf("Commands = %+v", got)
			}
			if got[0].Payload != first.Payload || !got[0].ExpiresAt.Equal(first.ExpiresAt) || !got[0].Open(now) || got[2].Open(now) {
				t.Fatalf("command round trip: %+v", got[0])
			}

			// finishing before leasing is refused
			if ok, err := s.FinishCommand(ctx, agent, first.ID, CommandSucceeded, "{}", "", now); err != nil || ok {
				t.Fatalf("finish unleased: ok=%v err=%v", ok, err)
			}
			// leased once
			if ok, err := s.LeaseCommand(ctx, agent, first.ID, now); err != nil || !ok {
				t.Fatalf("lease: ok=%v err=%v", ok, err)
			}
			if ok, err := s.LeaseCommand(ctx, agent, first.ID, now); err != nil || ok {
				t.Fatalf("lease again: ok=%v err=%v", ok, err)
			}
			// another agent cannot lease or finish it
			if ok, err := s.LeaseCommand(ctx, other.AgentID, second.ID, now); err != nil || ok {
				t.Fatalf("lease by another agent: ok=%v err=%v", ok, err)
			}
			if ok, err := s.FinishCommand(ctx, other.AgentID, first.ID, CommandSucceeded, "", "", now); err != nil || ok {
				t.Fatalf("finish by another agent: ok=%v err=%v", ok, err)
			}
			// expired and unknown commands are not leased
			if ok, err := s.LeaseCommand(ctx, agent, expired.ID, now); err != nil || ok {
				t.Fatalf("lease expired: ok=%v err=%v", ok, err)
			}
			if ok, err := s.LeaseCommand(ctx, agent, "01J0000000000000000000000Z", now); err != nil || ok {
				t.Fatalf("lease unknown: ok=%v err=%v", ok, err)
			}
			// a result is accepted once, and not after expiry
			if ok, err := s.LeaseCommand(ctx, agent, second.ID, now); err != nil || !ok {
				t.Fatalf("lease second: ok=%v err=%v", ok, err)
			}
			if ok, err := s.FinishCommand(ctx, agent, second.ID, CommandSucceeded, "", "", second.ExpiresAt); err != nil || ok {
				t.Fatalf("finish after expiry: ok=%v err=%v", ok, err)
			}
			if ok, err := s.FinishCommand(ctx, agent, first.ID, CommandFailed, `{"restored":[]}`, "boom", now); err != nil || !ok {
				t.Fatalf("finish: ok=%v err=%v", ok, err)
			}
			if ok, err := s.FinishCommand(ctx, agent, first.ID, CommandSucceeded, "", "", now); err != nil || ok {
				t.Fatalf("finish again: ok=%v err=%v", ok, err)
			}

			got, err = s.Commands(ctx, agent)
			if err != nil {
				t.Fatal(err)
			}
			f := got[0]
			if f.Status != CommandFailed || f.Error != "boom" || f.Result != `{"restored":[]}` || f.LeasedAt == nil || f.FinishedAt == nil || f.Open(now) {
				t.Fatalf("finished command: %+v", f)
			}
			if got[1].Status != CommandLeased || !got[1].Open(now) {
				t.Fatalf("leased command: %+v", got[1])
			}
		})
	}
}

func TestStore_CommandsSince(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			agent := "use1-blue-since-" + name
			idAt := func(at time.Time) string { return ulid.MustNew(ulid.Timestamp(at), rand.Reader).String() }
			old := idAt(now.Add(-time.Hour))
			edge := idAt(now.Add(-10 * time.Minute))
			fresh := idAt(now)
			for _, id := range []string{fresh, old, edge} {
				c := CommandRecord{AgentID: agent, ID: id, Type: protocol.CommandKeysRestore, Status: CommandQueued, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Payload: `{}`}
				if err := s.PutCommand(ctx, c); err != nil {
					t.Fatal(err)
				}
			}
			// the agent's state shares the partition and is not a command
			if err := s.PutAgentState(ctx, AgentState{AgentID: agent, LastCheckIn: now}); err != nil {
				t.Fatal(err)
			}

			got, err := s.CommandsSince(ctx, agent, now.Add(-10*time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 || got[0].ID != edge || got[1].ID != fresh || got[1].Payload != `{}` {
				t.Fatalf("CommandsSince = %+v", got)
			}
			if got, err := s.CommandsSince(ctx, agent, now.Add(time.Minute)); err != nil || len(got) != 0 {
				t.Fatalf("CommandsSince(future) = %+v, %v", got, err)
			}
			if got, err := s.CommandsSince(ctx, agent, time.Time{}); err != nil || len(got) != 3 {
				t.Fatalf("CommandsSince(zero) = %+v, %v", got, err)
			}
		})
	}
}

// queryRecorder is a DynamoDB client that records queries and finds
// nothing.
type queryRecorder struct {
	DynamoAPI
	queries []*dynamodb.QueryInput
}

func (q *queryRecorder) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	q.queries = append(q.queries, in)
	return &dynamodb.QueryOutput{}, nil
}

// A poll reads recent commands as a key range, so DynamoDB reads (and
// bills) only those, not every command kept until its TTL.
func TestDynamo_CommandsSinceReadsAKeyRange(t *testing.T) {
	api := &queryRecorder{}
	since := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	if _, err := NewDynamo(api, "t").CommandsSince(context.Background(), "use1-blue", since); err != nil {
		t.Fatal(err)
	}
	in := api.queries[0]
	from := in.ExpressionAttributeValues[":from"].(*types.AttributeValueMemberS).Value
	to := in.ExpressionAttributeValues[":to"].(*types.AttributeValueMemberS).Value
	if *in.KeyConditionExpression != "pk = :pk AND sk BETWEEN :from AND :to" || in.FilterExpression != nil {
		t.Fatalf("query = %q, filter %v", *in.KeyConditionExpression, in.FilterExpression)
	}
	want := "CMD#" + ulid.MustNew(ulid.Timestamp(since), nil).String()
	if from != want || !strings.HasSuffix(want, "0000000000000000") || to != "CMD#~" {
		t.Fatalf("range = %s .. %s, want from %s", from, to, want)
	}
}

func TestStore_CountRequest(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			key := "seals#" + name + "-" + time.Now().Format("150405.000000")
			end := time.Now().Add(time.Minute).Truncate(time.Minute)
			for i, want := range []bool{true, true, false, false} {
				if ok, err := s.CountRequest(ctx, key, 1, 2, end); err != nil || ok != want {
					t.Fatalf("request %d: ok=%v err=%v, want %v", i, ok, err, want)
				}
			}
			// the next window, and another key, count afresh
			if ok, err := s.CountRequest(ctx, key, 1, 2, end.Add(time.Minute)); err != nil || !ok {
				t.Fatalf("next window: ok=%v err=%v", ok, err)
			}
			if ok, err := s.CountRequest(ctx, key+"-other", 1, 2, end); err != nil || !ok {
				t.Fatalf("other key: ok=%v err=%v", ok, err)
			}

			// calls counted by weight: one under the limit counts whole, and
			// a check (0) only says whether the limit is reached
			weighed := key + "-weighed"
			for i, step := range []struct {
				n    int
				want bool
			}{{0, true}, {9, true}, {0, true}, {5, true}, {0, false}, {1, false}} {
				if ok, err := s.CountRequest(ctx, weighed, step.n, 10, end); err != nil || ok != step.want {
					t.Fatalf("weighed step %d (%d): ok=%v err=%v, want %v", i, step.n, ok, err, step.want)
				}
			}
		})
	}
}

func TestStore_Escrow(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			fp := "SHA256:escrow-" + name
			upload := func(agent, ciphertext string) protocol.EscrowRecord {
				return protocol.EscrowRecord{
					Fingerprint: fp,
					Certificate: "PEM",
					Envelope: protocol.Envelope{
						KeyID: "arn:aws:kms:us-east-1:000000000000:key/k", WrappedKey: "d3JhcHBlZA==", Nonce: "bm9uY2U=", Ciphertext: ciphertext,
						Context: map[string]string{"env": "dev", "fingerprint": fp, "purpose": "key-escrow"},
					},
					UploadedBy: agent,
					UploadedAt: time.Now().UTC().Truncate(time.Millisecond),
				}
			}
			if recs, err := s.Escrow(ctx, fp); err != nil || len(recs) != 0 {
				t.Fatalf("escrow before upload: %v %v", recs, err)
			}
			first := upload("use1-blue", "Zmlyc3Q=")
			if stored, isFirst, err := s.PutEscrow(ctx, first, 3); err != nil || !stored || !isFirst {
				t.Fatalf("first upload: stored=%v first=%v err=%v", stored, isFirst, err)
			}
			// one copy per agent: the first uploader cannot add or replace one
			if stored, _, err := s.PutEscrow(ctx, upload("use1-blue", "YWdhaW4="), 3); err != nil || stored {
				t.Fatalf("second upload by the same agent: stored=%v err=%v", stored, err)
			}
			// other agents add copies, up to three in all
			for _, agent := range []string{"use2-green", "use2-blue"} {
				if stored, isFirst, err := s.PutEscrow(ctx, upload(agent, "Y29weQ=="), 3); err != nil || !stored || isFirst {
					t.Fatalf("copy from %s: stored=%v first=%v err=%v", agent, stored, isFirst, err)
				}
			}
			if stored, _, err := s.PutEscrow(ctx, upload("use2-blue", "YWdhaW4="), 3); err != nil || stored {
				t.Fatalf("second copy from use2-blue: stored=%v err=%v", stored, err)
			}
			if stored, _, err := s.PutEscrow(ctx, upload("use3-blue", "Zm91cnRo"), 3); err != nil || stored {
				t.Fatalf("fourth copy: stored=%v err=%v", stored, err)
			}

			recs, err := s.Escrow(ctx, fp)
			if err != nil {
				t.Fatal(err)
			}
			var by []string
			for _, r := range recs {
				by = append(by, r.UploadedBy)
			}
			if !slices.Equal(by, []string{"use1-blue", "use2-blue", "use2-green"}) {
				t.Fatalf("copies = %v, want the primary first, then by uploader", by)
			}
			if got := recs[0]; got.Envelope.Ciphertext != "Zmlyc3Q=" || got.Envelope.Context["fingerprint"] != fp || !got.UploadedAt.Equal(first.UploadedAt) {
				t.Fatalf("escrow round trip: %+v", got)
			}

			fps := []string{fp, fp, "SHA256:none"}
			for i := range 120 {
				fps = append(fps, "SHA256:missing-"+time.Duration(i).String())
			}
			uploaders, err := s.EscrowUploaders(ctx, fps)
			if err != nil {
				t.Fatal(err)
			}
			if len(uploaders) != 1 || !slices.Equal(uploaders[fp], []string{"use1-blue", "use2-blue", "use2-green"}) {
				t.Fatalf("EscrowUploaders = %v", uploaders)
			}
		})
	}
}

func TestStore_KeyStatus(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			fp := "SHA256:status-" + name
			k := KeyRecord{Fingerprint: fp, Certificate: "PEM", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), FirstSeenAgent: "use1-blue", FirstSeenAt: now}

			revoke := k
			revoke.Status, revoke.StatusBy, revoke.StatusAt = KeyRevoked, "alice", &now
			if ok, err := s.SetKeyStatus(ctx, revoke); err != nil || ok {
				t.Fatalf("status of an unknown key: ok=%v err=%v", ok, err)
			}
			if revoked, err := s.RevokedKeys(ctx); err != nil || len(revoked) != 0 {
				t.Fatalf("an unknown key was listed as revoked: %v %v", revoked, err)
			}

			if _, err := s.PutKeyIfAbsent(ctx, k); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.GetKey(ctx, fp)
			if err != nil || !ok || got.Status != "" || got.Certificate != "PEM" {
				t.Fatalf("new key: %+v %v %v", got, ok, err)
			}
			if ok, err := s.SetKeyStatus(ctx, revoke); err != nil || !ok {
				t.Fatalf("revoke: ok=%v err=%v", ok, err)
			}
			got, _, _ = s.GetKey(ctx, fp)
			if got.Status != KeyRevoked || got.StatusBy != "alice" || got.StatusAt == nil || !got.StatusAt.Equal(now) || got.FirstSeenAgent != "use1-blue" {
				t.Fatalf("revoked key: %+v", got)
			}
			revoked, err := s.RevokedKeys(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if r := revoked[fp]; len(revoked) != 1 || r.By != "alice" || !r.At.Equal(now) || !r.NotBefore.Equal(k.NotBefore) {
				t.Fatalf("RevokedKeys = %+v", revoked)
			}

			later := now.Add(time.Minute)
			reinstate := k
			reinstate.Status, reinstate.StatusBy, reinstate.StatusAt = KeyActive, "bob", &later
			if ok, err := s.SetKeyStatus(ctx, reinstate); err != nil || !ok {
				t.Fatalf("reinstate: ok=%v err=%v", ok, err)
			}
			got, _, _ = s.GetKey(ctx, fp)
			if got.Status != KeyActive || got.StatusBy != "bob" {
				t.Fatalf("reinstated key: %+v", got)
			}
			if revoked, err := s.RevokedKeys(ctx); err != nil || len(revoked) != 0 {
				t.Fatalf("a reinstated key is still listed: %v %v", revoked, err)
			}
		})
	}
}

func TestStore_DeleteKey(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			fp := "SHA256:delete-" + name + "-" + now.Format("150405.000000")
			k := KeyRecord{Fingerprint: fp, Certificate: "PEM", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), FirstSeenAgent: "use1-blue", FirstSeenAt: now}
			if _, err := s.PutKeyIfAbsent(ctx, k); err != nil {
				t.Fatal(err)
			}
			for _, agent := range []string{"use1-blue", "use1-green"} {
				rec := protocol.EscrowRecord{
					Fingerprint: fp, Certificate: "PEM", UploadedBy: agent, UploadedAt: now,
					Envelope: protocol.Envelope{KeyID: "k", WrappedKey: "d3JhcHBlZA==", Nonce: "bm9uY2U=", Ciphertext: "Y29weQ==", Context: map[string]string{"fingerprint": fp}},
				}
				if stored, _, err := s.PutEscrow(ctx, rec, 3); err != nil || !stored {
					t.Fatalf("escrow from %s: stored=%v err=%v", agent, stored, err)
				}
			}
			later := now.Add(time.Minute)
			purge := later.Add(30 * 24 * time.Hour)
			del := k
			del.Status, del.StatusBy, del.StatusAt, del.PurgeAt = KeyDeleted, "bob", &later, &purge

			// only a revoked key is deleted
			if err := s.DeleteKey(ctx, del); !errors.Is(err, ErrKeyChanged) {
				t.Fatalf("delete of an active key: %v", err)
			}
			unknown := del
			unknown.Fingerprint = fp + "-unknown"
			if err := s.DeleteKey(ctx, unknown); !errors.Is(err, ErrKeyChanged) {
				t.Fatalf("delete of an unknown key: %v", err)
			}
			revoke := k
			revoke.Status, revoke.StatusBy, revoke.StatusAt = KeyRevoked, "alice", &now
			if ok, err := s.SetKeyStatus(ctx, revoke); err != nil || !ok {
				t.Fatalf("revoke: ok=%v err=%v", ok, err)
			}
			if err := s.DeleteKey(ctx, del); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if err := s.DeleteKey(ctx, del); !errors.Is(err, ErrKeyChanged) {
				t.Fatalf("delete again: %v", err)
			}
			got, _, _ := s.GetKey(ctx, fp)
			if got.Status != KeyDeleted || got.StatusBy != "bob" || got.PurgeAt == nil || !got.PurgeAt.Equal(purge) || !got.Revoked() {
				t.Fatalf("deleted key: %+v", got)
			}
			revoked, err := s.RevokedKeys(ctx)
			if err != nil {
				t.Fatal(err)
			}
			r := revoked[fp]
			if !r.Deleted() || r.By != "alice" || !r.At.Equal(now) || r.DeletedBy != "bob" || r.DeletedAt == nil || !r.DeletedAt.Equal(later) ||
				r.PurgeAt == nil || !r.PurgeAt.Equal(purge) || r.Purged(later) || !r.Purged(purge) {
				t.Fatalf("deleted key's record: %+v", r)
			}
			// a deleted key changes status only through reinstating it
			if ok, err := s.SetKeyStatus(ctx, revoke); !errors.Is(err, ErrKeyChanged) || ok {
				t.Fatalf("revoke of a deleted key: ok=%v err=%v", ok, err)
			}
			// its copies are kept until the purge, and no copy is added
			if recs, err := s.Escrow(ctx, fp); err != nil || len(recs) != 2 {
				t.Fatalf("escrow of a deleted key: %d %v", len(recs), err)
			}
			extra := protocol.EscrowRecord{Fingerprint: fp, Certificate: "PEM", UploadedBy: "use2-blue", UploadedAt: now,
				Envelope: protocol.Envelope{KeyID: "k", WrappedKey: "d3JhcHBlZA==", Nonce: "bm9uY2U=", Ciphertext: "Y29weQ==", Context: map[string]string{}}}
			if stored, _, err := s.PutEscrow(ctx, extra, 3); err != nil || stored {
				t.Fatalf("copy of a deleted key: stored=%v err=%v", stored, err)
			}

			reinstate := k
			reinstate.Status, reinstate.StatusBy, reinstate.StatusAt = KeyActive, "carol", &later
			if err := s.ReinstateDeletedKey(ctx, reinstate); err != nil {
				t.Fatalf("reinstate: %v", err)
			}
			if err := s.ReinstateDeletedKey(ctx, reinstate); !errors.Is(err, ErrKeyChanged) {
				t.Fatalf("reinstate again: %v", err)
			}
			got, _, _ = s.GetKey(ctx, fp)
			if got.Status != KeyActive || got.StatusBy != "carol" || got.PurgeAt != nil {
				t.Fatalf("reinstated key: %+v", got)
			}
			if revoked, _ := s.RevokedKeys(ctx); len(revoked) != 0 {
				t.Fatalf("a reinstated key is still listed: %v", revoked)
			}
			// its copies no longer expire, so new ones may be added again
			if stored, _, err := s.PutEscrow(ctx, extra, 3); err != nil || !stored {
				t.Fatalf("copy of a reinstated key: stored=%v err=%v", stored, err)
			}

			// deleted again, with a purge time already past: its copies are
			// gone to every read, whether or not TTL has removed them
			past := now.Add(-time.Second)
			if ok, err := s.SetKeyStatus(ctx, revoke); err != nil || !ok {
				t.Fatalf("revoke again: ok=%v err=%v", ok, err)
			}
			del.PurgeAt = &past
			if err := s.DeleteKey(ctx, del); err != nil {
				t.Fatalf("delete with a past purge: %v", err)
			}
			if recs, err := s.Escrow(ctx, fp); err != nil || len(recs) != 0 {
				t.Fatalf("escrow past the purge: %d %v", len(recs), err)
			}
			if up, err := s.EscrowUploaders(ctx, []string{fp}); err != nil || len(up) != 0 {
				t.Fatalf("uploaders past the purge: %v %v", up, err)
			}
		})
	}
}

// A key with no escrowed copy is deleted all the same; a copy stored
// between the read of its copies and the write would be left without its
// purge time, so the write is refused then.
func TestStore_DeleteKeyWithoutEscrow(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			fp := "SHA256:delete-bare-" + name + "-" + now.Format("150405.000000")
			k := KeyRecord{Fingerprint: fp, Certificate: "PEM", FirstSeenAt: now}
			if _, err := s.PutKeyIfAbsent(ctx, k); err != nil {
				t.Fatal(err)
			}
			revoke := k
			revoke.Status, revoke.StatusBy, revoke.StatusAt = KeyRevoked, "alice", &now
			if ok, err := s.SetKeyStatus(ctx, revoke); err != nil || !ok {
				t.Fatalf("revoke: ok=%v err=%v", ok, err)
			}
			purge := now.Add(time.Hour)
			del := k
			del.Status, del.StatusBy, del.StatusAt, del.PurgeAt = KeyDeleted, "bob", &now, &purge
			if err := s.DeleteKey(ctx, del); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if got, _, _ := s.GetKey(ctx, fp); got.Status != KeyDeleted {
				t.Fatalf("status = %q", got.Status)
			}
		})
	}
}

func TestStore_KeyUsage(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			agent := "use1-blue-usage-" + name
			u := KeyUsage{
				AgentID: agent, CountedAt: now, ScannedAt: now.Add(-time.Second),
				Namespaces: []string{"apps", "sealed-secrets"}, SealedSecrets: 3, Values: 5, Unmatched: 1,
				Keys: map[string]KeyUse{"SHA256:a/b+c=": {Values: 4, SealedSecrets: 2}},
			}
			if stored, err := s.PutKeyUsage(ctx, u); err != nil || !stored {
				t.Fatalf("put: stored=%v err=%v", stored, err)
			}
			// the same report again keeps the time it was first received
			again := u
			again.CountedAt = now.Add(time.Minute)
			if stored, err := s.PutKeyUsage(ctx, again); err != nil || stored {
				t.Fatalf("put again: stored=%v err=%v", stored, err)
			}
			// the agent state shares the partition and is not usage
			if err := s.PutAgentState(ctx, AgentState{AgentID: agent, LastCheckIn: now}); err != nil {
				t.Fatal(err)
			}
			got, err := s.KeyUsages(ctx, []string{agent, "missing"})
			if err != nil {
				t.Fatal(err)
			}
			g := got[agent]
			if len(got) != 1 || !g.CountedAt.Equal(now) || !g.ScannedAt.Equal(u.ScannedAt) || !slices.Equal(g.Namespaces, u.Namespaces) ||
				g.SealedSecrets != 3 || g.Values != 5 || g.Unmatched != 1 || g.Keys["SHA256:a/b+c="] != (KeyUse{Values: 4, SealedSecrets: 2}) {
				t.Fatalf("usage round trip: %+v", got)
			}

			// a newer report replaces it; a failed one has no counts and
			// every namespace reads as none
			failed := KeyUsage{AgentID: agent, CountedAt: now.Add(2 * time.Minute), ScannedAt: now.Add(time.Minute), Error: "forbidden"}
			if stored, err := s.PutKeyUsage(ctx, failed); err != nil || !stored {
				t.Fatalf("put failed: stored=%v err=%v", stored, err)
			}
			got, _ = s.KeyUsages(ctx, []string{agent})
			if g := got[agent]; g.Error != "forbidden" || len(g.Keys) != 0 || len(g.Namespaces) != 0 || g.Values != 0 {
				t.Fatalf("failed usage: %+v", g)
			}
		})
	}
}
