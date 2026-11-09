package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCerts returns the queued responses in order, repeating the last one.
type fakeCerts struct {
	mu        sync.Mutex
	responses []fakeResponse
}

type fakeResponse struct {
	pem []byte
	err error
}

func (f *fakeCerts) ActiveCert(context.Context) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.responses[0]
	if len(f.responses) > 1 {
		f.responses = f.responses[1:]
	}
	return r.pem, r.err
}

func newTestAgent(certs CertSource) (*Agent, *bytes.Buffer) {
	var logs bytes.Buffer
	a := New(Options{
		Certs:    certs,
		Interval: time.Minute,
		Logger:   slog.New(slog.NewTextHandler(&logs, nil)),
		Version:  "test",
	})
	return a, &logs
}

func probe(t *testing.T, a *Agent, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

func TestAgent_ReadyOnlyAfterCertRead(t *testing.T) {
	good := selfSigned(t, rsaKey(t, 2048), time.Now().Add(-time.Hour))
	certs := &fakeCerts{responses: []fakeResponse{
		{err: errors.New("controller not up")},
		{pem: good},
	}}
	a, logs := newTestAgent(certs)

	if got := probe(t, a, "/healthz"); got != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", got)
	}

	a.refresh(context.Background())
	if got := probe(t, a, "/readyz"); got != http.StatusServiceUnavailable {
		t.Fatalf("/readyz after failed read = %d, want 503", got)
	}
	if !strings.Contains(logs.String(), "event=controller.cert_failed") {
		t.Errorf("failed read was not logged:\n%s", logs)
	}

	a.refresh(context.Background())
	if got := probe(t, a, "/readyz"); got != http.StatusOK {
		t.Fatalf("/readyz after good read = %d, want 200", got)
	}
	if _, ok := a.ActiveKey(); !ok {
		t.Fatal("ActiveKey reports nothing after a good read")
	}
}

func TestAgent_LogsOnlyKeyChanges(t *testing.T) {
	first := selfSigned(t, rsaKey(t, 2048), time.Now().Add(-time.Hour))
	second := selfSigned(t, rsaKey(t, 2048), time.Now().Add(-time.Minute))
	certs := &fakeCerts{responses: []fakeResponse{{pem: first}, {pem: first}, {pem: second}}}
	a, logs := newTestAgent(certs)

	for range 3 {
		a.refresh(context.Background())
	}
	if n := strings.Count(logs.String(), "event=controller.key_active"); n != 2 {
		t.Errorf("logged %d key changes, want 2:\n%s", n, logs)
	}
}

func TestAgent_KeepsLastKeyWhenReadFails(t *testing.T) {
	good := selfSigned(t, rsaKey(t, 2048), time.Now().Add(-time.Hour))
	certs := &fakeCerts{responses: []fakeResponse{{pem: good}, {pem: []byte("junk")}}}
	a, _ := newTestAgent(certs)

	a.refresh(context.Background())
	before, _ := a.ActiveKey()
	a.refresh(context.Background())
	after, ok := a.ActiveKey()
	if !ok || after.Fingerprint != before.Fingerprint {
		t.Fatalf("active key changed after a bad read: %+v -> %+v", before, after)
	}
}

func TestAgent_RunStopsWithContext(t *testing.T) {
	good := selfSigned(t, rsaKey(t, 2048), time.Now().Add(-time.Hour))
	a, _ := newTestAgent(&fakeCerts{responses: []fakeResponse{{pem: good}}})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
