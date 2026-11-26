package main

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestVerifyRetentionRequiresComplianceAndExactUntil(t *testing.T) {
	until := time.Date(2035, 4, 5, 6, 7, 8, 0, time.UTC)
	want := objectSnapshot{version: "v1", mode: types.ObjectLockRetentionModeCompliance, until: until}
	got := s3.GetObjectRetentionOutput{Retention: &types.ObjectLockRetention{Mode: types.ObjectLockRetentionModeCompliance, RetainUntilDate: &until}}
	if err := verifyRetention(got, want); err != nil {
		t.Fatalf("valid retention rejected: %v", err)
	}
	wrong := until.Add(time.Second)
	got.Retention.RetainUntilDate = &wrong
	if verifyRetention(got, want) == nil {
		t.Fatal("accepted changed retain-until")
	}
	got.Retention.RetainUntilDate = &until
	got.Retention.Mode = types.ObjectLockRetentionModeGovernance
	if verifyRetention(got, want) == nil {
		t.Fatal("accepted non-Compliance mode")
	}
}
func TestVerifyOriginalRequiresExactVersionAndSHA256(t *testing.T) {
	body := []byte("synthetic payload")
	until := time.Date(2035, 4, 5, 6, 7, 8, 0, time.UTC)
	want := objectSnapshot{version: "v1", digest: sha256.Sum256(body), mode: types.ObjectLockRetentionModeCompliance, until: until}
	good := s3.GetObjectOutput{VersionId: ptr("v1"), Body: io.NopCloser(bytes.NewReader(body))}
	if err := verifySnapshot(good, want); err != nil {
		t.Fatalf("valid readback rejected: %v", err)
	}
	bad := s3.GetObjectOutput{VersionId: ptr("v2"), Body: io.NopCloser(bytes.NewReader(body))}
	if verifySnapshot(bad, want) == nil {
		t.Fatal("accepted different version id")
	}
	bad = s3.GetObjectOutput{VersionId: ptr("v1"), Body: io.NopCloser(bytes.NewReader([]byte("changed")))}
	if verifySnapshot(bad, want) == nil {
		t.Fatal("accepted changed bytes")
	}
}
func ptr(s string) *string { return &s }
