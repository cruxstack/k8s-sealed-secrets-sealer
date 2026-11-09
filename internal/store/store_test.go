package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

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
			if !g.LastCheckIn.Equal(now) || g.Controller.ActiveFingerprint != "SHA256:a" || len(g.Keys) != 1 || !g.KeysComplete {
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
