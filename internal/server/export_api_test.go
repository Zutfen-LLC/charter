package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExportRequestDecoderRejectsAmbiguousOrClientTenant(t *testing.T) {
	type payload struct {
		ProjectID string `json:"project_id"`
	}
	for _, raw := range []string{`{"project_id":"a","project_id":"b"}`, `{"project_id":"a","tenant_id":"caller-asserted"}`, `{"project_id":"a"}{}`, `{"project_id":"a","Project_ID":"b"}`, `null`} {
		r := httptest.NewRequest("POST", "/v1/exports", strings.NewReader(raw))
		var p payload
		if err := decodeExportRequest(r, &p, "project_id"); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	r := httptest.NewRequest("POST", "/v1/exports", strings.NewReader(`{"project_id":"a"}`))
	var p payload
	if err := decodeExportRequest(r, &p, "project_id"); err != nil || p.ProjectID != "a" {
		t.Fatalf("valid input rejected: %v", err)
	}
}
