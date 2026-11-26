package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestC05CallBodyRefusesTransportFieldsAndTrailingValues(t *testing.T) {
	for _, raw := range []string{
		`{"input":"synthetic","endpoint":"http://127.0.0.1:1"}`,
		`{"input":"synthetic","provider":"other"}`,
		`{"input":"synthetic","credentials":"synthetic"}`,
		`{"input":"synthetic","destination_class":"local"}`,
		`{"input":"synthetic"} {"endpoint":"http://127.0.0.1:1"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(raw))
		w := httptest.NewRecorder()
		if _, ok := (&Auth{}).readCallBody(w, req); ok || w.Code != http.StatusBadRequest {
			t.Errorf("request transport override syntax accepted: status=%d", w.Code)
		}
	}
}
