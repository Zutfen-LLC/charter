package evidence

import (
	"encoding/json"
	"testing"
)

func TestC05IdempotencyBindsRequestedModel(t *testing.T) {
	fingerprint := func(body string) string {
		t.Helper()
		var r Request
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatal(err)
		}
		fp, err := Fingerprint(r)
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}
	a := fingerprint(`{"ModelID":"deterministic-a","RequestID":"one"}`)
	if b := fingerprint(`{"ModelID":"deterministic-a","RequestID":"two"}`); a != b {
		t.Fatal("request ID changed replay identity")
	}
	if b := fingerprint(`{"ModelID":"deterministic-b","RequestID":"one"}`); a == b {
		t.Fatal("different requested models shared a replay identity")
	}
}
