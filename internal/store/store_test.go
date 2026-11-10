package store

import (
	"context"
	"crypto/rand"
	"os"
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

				CheckInIntervalSeconds: 60,
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
		})
	}
}

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

func TestStore_Escrow(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			fp := "SHA256:escrow-" + name
			rec := protocol.EscrowRecord{
				Fingerprint: fp,
				Certificate: "PEM",
				Envelope: protocol.Envelope{
					KeyID: "arn:aws:kms:us-east-1:000000000000:key/k", WrappedKey: "d3JhcHBlZA==", Nonce: "bm9uY2U=", Ciphertext: "Y2lwaGVy",
					Context: map[string]string{"env": "dev", "fingerprint": fp, "purpose": "key-escrow"},
				},
				UploadedBy: "use1-blue",
				UploadedAt: time.Now().UTC().Truncate(time.Millisecond),
			}
			if _, ok, err := s.Escrow(ctx, fp); err != nil || ok {
				t.Fatalf("escrow before upload: ok=%v err=%v", ok, err)
			}
			if stored, err := s.PutEscrowIfAbsent(ctx, rec); err != nil || !stored {
				t.Fatalf("first upload: stored=%v err=%v", stored, err)
			}
			second := rec
			second.UploadedBy = "use2-blue"
			if stored, err := s.PutEscrowIfAbsent(ctx, second); err != nil || stored {
				t.Fatalf("second upload: stored=%v err=%v", stored, err)
			}
			got, ok, err := s.Escrow(ctx, fp)
			if err != nil || !ok {
				t.Fatalf("escrow: ok=%v err=%v", ok, err)
			}
			if got.UploadedBy != "use1-blue" || got.Envelope.Ciphertext != "Y2lwaGVy" || got.Envelope.Context["fingerprint"] != fp || !got.UploadedAt.Equal(rec.UploadedAt) {
				t.Fatalf("escrow round trip: %+v", got)
			}

			fps := []string{fp, fp, "SHA256:none"}
			for i := range 120 {
				fps = append(fps, "SHA256:missing-"+time.Duration(i).String())
			}
			escrowed, err := s.Escrowed(ctx, fps)
			if err != nil {
				t.Fatal(err)
			}
			if len(escrowed) != 1 || !escrowed[fp] {
				t.Fatalf("Escrowed = %v", escrowed)
			}
		})
	}
}
