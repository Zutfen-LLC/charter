package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestHealthzFlagsTestEvidence(t *testing.T) {
	rec := get(t, New(fakeDB{}, TestFixtureBackend()), "/healthz")
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	b := rec.Body.String()
	if !strings.Contains(b, `"retention_enforced":false`) || !strings.Contains(b, "TEST EVIDENCE ONLY") {
		t.Fatalf("health must disclose test evidence: %s", b)
	}
}

func TestReadyzFailsClosedWhenDBDown(t *testing.T) {
	rec := get(t, New(fakeDB{errors.New("down")}, TestFixtureBackend()), "/readyz")
	if rec.Code != 503 {
		t.Fatalf("code %d, want 503", rec.Code)
	}
}

func TestReadyzOK(t *testing.T) {
	if rec := get(t, New(fakeDB{}, TestFixtureBackend()), "/readyz"); rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
}
