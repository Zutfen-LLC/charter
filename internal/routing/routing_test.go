package routing

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

func TestResolvePolicyAndDeterministicSwitch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy = Policy{AllowedModelIDs: []string{"det-a", "det-b"}}
	got, err := cfg.Resolve("det-a")
	if err != nil || got.ID != "det-a" {
		t.Fatalf("resolve: %#v %v", got, err)
	}
	got, err = cfg.Resolve("det-b")
	if err != nil || got.ID != "det-b" {
		t.Fatalf("resolve: %#v %v", got, err)
	}
	cfg.Policy = Policy{LocalOnly: true, AllowedModelIDs: []string{"hosted-test"}}
	if _, err := cfg.Resolve("hosted-test"); err == nil {
		t.Fatal("local_only allowed hosted model")
	}
	cfg.Policy = Policy{}
	if _, err := cfg.Resolve("det-a"); err == nil {
		t.Fatal("empty policy must deny")
	}
}

func TestHTTPAdapterSendsExactBytesOnce(t *testing.T) {
	body := []byte{0, 1, 2, '\n', 0xff}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("body mismatch: %v", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":"ok","usage":{"input_bytes":5,"output_bytes":2}}`))
	}))
	defer srv.Close()
	m := Model{ID: "local-http", Kind: KindLocalHTTP, Class: ClassLocal, Destination: evidenceDestination("test", "local", "local-model"), Endpoint: srv.URL, MaxRequestBytes: 10, MaxOutputBytes: 100, RequestByteRate: 1, OutputByteRate: 1}
	out, err := (HTTPAdapter{Timeout: time.Second}).Invoke(context.Background(), m, body)
	if err != nil || calls.Load() != 1 || string(out.ModelOutcome.Output) != "ok" || out.InputBytes != 5 || out.OutputBytes != 2 {
		t.Fatalf("out=%+v calls=%d err=%v", out, calls.Load(), err)
	}
}

func evidenceDestination(p, e, m string) evidence.Destination {
	return evidence.Destination{Provider: p, EndpointID: e, ModelID: m}
}
