package records

import (
	"testing"
	"time"
)

func TestCanonicalExportIntentSortsCustodiansAndBindsUTCWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	in := ExportIntent{ProjectID: "11111111-1111-4111-8111-111111111111", MatterID: "22222222-2222-4222-8222-222222222222", CustodianIDs: []string{"44444444-4444-4444-8444-444444444444", "33333333-3333-4333-8333-333333333333"}, WindowStart: start, WindowEnd: end, Reason: "review"}
	got, b, err := canonicalExportIntent(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.CustodianIDs[0] > got.CustodianIDs[1] {
		t.Fatalf("custodians not canonical: %v", got.CustodianIDs)
	}
	got2, b2, err := canonicalExportIntent(ExportIntent{ProjectID: in.ProjectID, MatterID: in.MatterID, CustodianIDs: []string{in.CustodianIDs[1], in.CustodianIDs[0]}, WindowStart: start, WindowEnd: end, Reason: "review"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(b2) || got.ProjectID != got2.ProjectID {
		t.Fatal("set-order permutations must bind to identical intent bytes")
	}
}

func TestCanonicalExportIntentRejectsNonUTCOrEmptyWindow(t *testing.T) {
	local := time.FixedZone("offset", 3600)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, local)
	in := ExportIntent{ProjectID: "11111111-1111-4111-8111-111111111111", MatterID: "22222222-2222-4222-8222-222222222222", WindowStart: start, WindowEnd: start, Reason: "review"}
	if _, _, err := canonicalExportIntent(in); err == nil {
		t.Fatal("empty half-open interval must be refused")
	}
}
