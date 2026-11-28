package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
)

func TestExportReadbackFencesExactVersionBeforeRead(t *testing.T) {
	body := []byte("original bytes")
	until := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	const key = "charter/v1/dep/tenant/data/objects/example"
	frozen := map[VersionRef]bool{{Key: key, Version: "retained"}: true}
	mem := &retainedMemory{objects: map[string]map[string]s3transport.Version{key: {
		"retained":    {ID: "retained", Data: body, Mode: "COMPLIANCE", Until: until},
		"substituted": {ID: "substituted", Data: body, Mode: "COMPLIANCE", Until: until},
	}}}
	b := &RetentionBackend{store: mem, deployment: "dep", bucket: "archive"}
	r := retainedObjectReceipt{Deployment: "dep", Bucket: "archive", Key: key, Version: "retained", SHA256: SHA256(body), Length: uint64(len(body)), RetainUntil: until.Format(time.RFC3339)}
	got, err := b.readExactExportVersion(context.Background(), r, frozen)
	if err != nil || string(got) != string(body) {
		t.Fatalf("expired COMPLIANCE version on independently held scope: %q %v", got, err)
	}
	r.Version = "substituted"
	if got, err := b.readExactExportVersion(context.Background(), r, frozen); !errors.Is(err, ErrConflict) || got != nil {
		t.Fatalf("allowed substitution: %q %v", got, err)
	}
}
