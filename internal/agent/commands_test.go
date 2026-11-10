package agent

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// queueClient hands out queued commands once and records results.
type queueClient struct {
	mu      sync.Mutex
	queue   []protocol.Command
	results map[string]protocol.CommandResult
	polls   int
}

func (q *queueClient) Commands(ctx context.Context, _ time.Duration) ([]protocol.Command, error) {
	q.mu.Lock()
	q.polls++
	out := q.queue
	q.queue = nil
	q.mu.Unlock()
	if len(out) == 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return out, nil
}

func (q *queueClient) Result(_ context.Context, id string, res protocol.CommandResult) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.results[id] = res
	return nil
}

func (q *queueClient) result(id string) (protocol.CommandResult, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	r, ok := q.results[id]
	return r, ok
}

func TestCommands_RunsHandlersAndReports(t *testing.T) {
	now := time.Now()
	q := &queueClient{results: map[string]protocol.CommandResult{}, queue: []protocol.Command{
		{ID: "ok", Type: protocol.CommandRenewalEnable, ExpiresAt: now.Add(time.Minute), Payload: json.RawMessage(`{"period":"720h"}`)},
		{ID: "fails", Type: protocol.CommandKeysRestore, ExpiresAt: now.Add(time.Minute), Payload: json.RawMessage(`{}`)},
		{ID: "unknown", Type: "exec.v1", ExpiresAt: now.Add(time.Minute)},
		{ID: "expired", Type: protocol.CommandRenewalEnable, ExpiresAt: now.Add(-time.Second)},
	}}
	c := NewCommands(q, nil, nil)
	var ran []string
	c.Handle(protocol.CommandRenewalEnable, func(_ context.Context, cmd protocol.Command) (any, error) {
		ran = append(ran, cmd.ID+" "+string(cmd.Payload))
		return map[string]string{"period": "720h0m0s"}, nil
	})
	c.Handle(protocol.CommandKeysRestore, func(context.Context, protocol.Command) (any, error) {
		return protocol.KeysRestoreResult{Failed: []protocol.KeyFailure{{Fingerprint: "SHA256:x", Error: "boom"}}}, errors.New(strings.Repeat("e", 2000))
	})
	if got := c.Types(); !slices.Equal(got, []string{protocol.CommandKeysRestore, protocol.CommandRenewalEnable}) {
		t.Fatalf("Types = %v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := q.result("unknown"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("commands were not run")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if r, _ := q.result("ok"); r.Status != protocol.CommandSucceeded || string(r.Result) != `{"period":"720h0m0s"}` || !slices.Equal(ran, []string{`ok {"period":"720h"}`}) {
		t.Errorf("ok = %+v", r)
	}
	if r, _ := q.result("fails"); r.Status != protocol.CommandFailed || len(r.Error) != maxErrorLen || !strings.Contains(string(r.Result), "boom") {
		t.Errorf("fails = %+v", r)
	}
	if r, _ := q.result("unknown"); r.Status != protocol.CommandFailed || r.Error != "unsupported command type" {
		t.Errorf("unknown = %+v", r)
	}
	if _, ok := q.result("expired"); ok {
		t.Error("an expired command was run or reported")
	}
}

func TestCommands_IdleWithoutHandlers(t *testing.T) {
	q := &queueClient{results: map[string]protocol.CommandResult{}}
	c := NewCommands(q, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if q.polls != 0 {
		t.Errorf("polled %d times with no handlers", q.polls)
	}
}
