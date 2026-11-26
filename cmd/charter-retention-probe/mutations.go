package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type objectSnapshot struct {
	version string
	digest  [32]byte
	mode    types.ObjectLockRetentionMode
	until   time.Time
}
type s3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	GetObjectRetention(context.Context, *s3.GetObjectRetentionInput, ...func(*s3.Options)) (*s3.GetObjectRetentionOutput, error)
	PutObjectRetention(context.Context, *s3.PutObjectRetentionInput, ...func(*s3.Options)) (*s3.PutObjectRetentionOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
}

func snapshot(body []byte, version string, mode types.ObjectLockRetentionMode, until time.Time) objectSnapshot {
	return objectSnapshot{version: version, digest: sha256.Sum256(body), mode: mode, until: until.UTC()}
}
func verifySnapshot(got s3.GetObjectOutput, want objectSnapshot) error {
	defer got.Body.Close()
	body, err := io.ReadAll(io.LimitReader(got.Body, 1<<20))
	if err != nil {
		return errors.New("readback body failed")
	}
	if got.VersionId == nil || *got.VersionId != want.version || sha256.Sum256(body) != want.digest {
		return errors.New("original exact version or SHA-256 mismatch")
	}
	return nil
}
func verifyRetention(got s3.GetObjectRetentionOutput, want objectSnapshot) error {
	if got.Retention == nil || got.Retention.Mode != want.mode || got.Retention.RetainUntilDate == nil || !got.Retention.RetainUntilDate.Equal(want.until) {
		return errors.New("exact-version retention readback mismatch")
	}
	return nil
}
func readExact(ctx context.Context, api s3API, bucket, key string, want objectSnapshot) error {
	out, err := api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(want.version)})
	if err != nil {
		return errors.New("exact-version body read failed")
	}
	if err = verifySnapshot(*out, want); err != nil {
		return err
	}
	r, err := api.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(want.version)})
	if err != nil {
		return errors.New("exact-version retention read failed")
	}
	return verifyRetention(*r, want)
}
func mint(ctx context.Context, api s3API, bucket, key string, body []byte, until time.Time) (objectSnapshot, error) {
	star := "*"
	out, err := api.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(body), ContentLength: aws.Int64(int64(len(body))), ChecksumAlgorithm: types.ChecksumAlgorithmSha256, IfNoneMatch: &star, ObjectLockMode: types.ObjectLockModeCompliance, ObjectLockRetainUntilDate: &until})
	if err != nil || out.VersionId == nil || *out.VersionId == "" {
		return objectSnapshot{}, errors.New("synthetic object creation or version id missing")
	}
	s := snapshot(body, *out.VersionId, types.ObjectLockRetentionModeCompliance, until)
	if err := readExact(ctx, api, bucket, key, s); err != nil {
		return objectSnapshot{}, err
	}
	return s, nil
}
func expectedGuardRefusal(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "AccessDenied", "AccessDeniedByRetention", "InvalidRequest", "ObjectLocked":
		return true
	}
	return false
}
func exactVersionPresent(ctx context.Context, api s3API, bucket, key, version string) (bool, error) {
	out, err := api.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket), Prefix: aws.String(key)})
	if err != nil {
		return false, errors.New("version census failed")
	}
	for _, v := range out.Versions {
		if v.Key != nil && *v.Key == key && v.VersionId != nil && *v.VersionId == version {
			return true, nil
		}
	}
	return false, nil
}
func attemptDelete(ctx context.Context, api s3API, bucket, key string, want objectSnapshot) error {
	_, err := api.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(want.version)})
	if err == nil {
		present, censusErr := exactVersionPresent(ctx, api, bucket, key, want.version)
		if censusErr != nil {
			return errors.New("delete succeeded but exact-version readback is inconclusive")
		}
		if present {
			if readErr := readExact(ctx, api, bucket, key, want); readErr != nil {
				return errors.New("delete succeeded and original version readback failed")
			}
			return errors.New("exact-version delete was allowed; original version and retention remain")
		}
		return errors.New("exact-version delete was allowed; original version was removed")
	}
	if !expectedGuardRefusal(err) {
		return errors.New("delete returned an unrecognized error; refusal is inconclusive")
	}
	if verifyErr := readExact(ctx, api, bucket, key, want); verifyErr != nil {
		return fmt.Errorf("delete outcome inconclusive: %w", verifyErr)
	}
	return nil
}
func retention(ctx context.Context, api s3API, bucket, key string, want objectSnapshot, until time.Time) error {
	_, err := api.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(want.version), Retention: &types.ObjectLockRetention{Mode: want.mode, RetainUntilDate: &until}})
	return err
}
func reportSnapshot(status, label string, snap objectSnapshot) {
	fmt.Printf("%s %s version=%q sha256=%x retention=%s retain_until=%s\n", status, label, snap.version, snap.digest, snap.mode, snap.until.UTC().Format(time.RFC3339))
}
func runMutations(ctx context.Context, rt, ad s3API, bucket, prefix string) error {
	body := []byte("charter-c04 synthetic retention qualification object\n")
	initial := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second)
	key := prefix + "protected-version"
	base, err := mint(ctx, rt, bucket, key, body, initial)
	if err != nil {
		return err
	}
	reportSnapshot("ALLOWED", "runtime-created protected object", base)
	// Same administrator first proves its retention authority with a legal extension.
	extended := initial.Add(48 * time.Hour)
	if err = retention(ctx, ad, bucket, key, base, extended); err != nil {
		return errors.New("administrator extension positive control failed")
	}
	adminBase := base
	adminBase.until = extended
	if err = readExact(ctx, rt, bucket, key, adminBase); err != nil {
		return errors.New("administrator extension positive-control readback failed")
	}
	reportSnapshot("ALLOWED", "administrator retention extension positive control", adminBase)
	shortenErr := retention(ctx, ad, bucket, key, adminBase, initial)
	if shortenErr == nil {
		shortened := adminBase
		shortened.until = initial
		if readErr := readExact(ctx, rt, bucket, key, shortened); readErr != nil {
			return errors.New("administrator shortening was accepted but the resulting state is inconclusive")
		}
		reportSnapshot("ALLOWED", "administrator Compliance shortening", shortened)
		return errors.New("administrator Compliance shortening violated the retention guard")
	}
	if !expectedGuardRefusal(shortenErr) {
		return errors.New("administrator shortening returned an unrecognized error; inconclusive")
	}
	if err = readExact(ctx, rt, bucket, key, adminBase); err != nil {
		return fmt.Errorf("administrator shortening refusal not verified: %w", err)
	}
	reportSnapshot("REFUSED", "administrator active Compliance shortening; readback verified", adminBase)
	if err = attemptDelete(ctx, ad, bucket, key, adminBase); err != nil {
		return fmt.Errorf("administrator exact-version delete: %w", err)
	}
	reportSnapshot("REFUSED", "administrator exact-version DeleteObject; readback verified", adminBase)
	if err = attemptDelete(ctx, rt, bucket, key, adminBase); err != nil {
		return fmt.Errorf("runtime exact-version delete: %w", err)
	}
	reportSnapshot("REFUSED", "runtime exact-version DeleteObject; readback verified", adminBase)
	return nil
}
func runConditionalRaces(ctx context.Context, api s3API, bucket, prefix string) error {
	occupiedKey := prefix + "race-occupied"
	occupied, err := mint(ctx, api, bucket, occupiedKey, []byte("occupied baseline"), time.Now().UTC().Add(72*time.Hour).Truncate(time.Second))
	if err != nil {
		return errors.New("cannot create occupied race baseline")
	}
	occupiedRace, err := raceCreates(ctx, api, bucket, occupiedKey, 32)
	if err != nil || occupiedRace.winners != 0 || occupiedRace.rejected != 32 {
		return errors.New("occupied conditional race did not reject all 32 writers with precondition failures")
	}
	count, err := versionCount(ctx, api, bucket, occupiedKey)
	if err != nil || count != 1 {
		return errors.New("occupied race exact version census is not one")
	}
	if err = readExact(ctx, api, bucket, occupiedKey, occupied); err != nil {
		return errors.New("occupied race changed baseline bytes or retention")
	}
	fmt.Println("REFUSED conditional writes to occupied key: 32/32; exact version census=1")
	emptyKey := prefix + "race-empty"
	emptyRace, err := raceCreates(ctx, api, bucket, emptyKey, 32)
	if err != nil || emptyRace.winners != 1 || emptyRace.rejected != 31 {
		return errors.New("empty conditional race did not produce exactly one winner and 31 precondition failures")
	}
	count, err = versionCount(ctx, api, bucket, emptyKey)
	if err != nil || count != 1 {
		return errors.New("empty race exact version census is not one")
	}
	fmt.Println("ALLOWED conditional create on empty key: exactly 1/32; exact version census=1")
	return nil
}

type raceCounts struct{ winners, rejected int }

func expectedConditionalRejection(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && (apiErr.ErrorCode() == "PreconditionFailed" || apiErr.ErrorCode() == "ConditionalRequestConflict")
}
func raceCreates(ctx context.Context, api s3API, bucket, key string, n int) (raceCounts, error) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := raceCounts{}
	unexpected := false
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			data := []byte(fmt.Sprintf("race-%02d", i))
			star := "*"
			out, err := api.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(data), ContentLength: aws.Int64(int64(len(data))), IfNoneMatch: &star})
			mu.Lock()
			defer mu.Unlock()
			if err == nil && out.VersionId != nil && *out.VersionId != "" {
				counts.winners++
			} else if expectedConditionalRejection(err) {
				counts.rejected++
			} else {
				unexpected = true
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if unexpected || counts.winners+counts.rejected != n {
		return counts, errors.New("conditional race had an unexpected or unaccounted result")
	}
	return counts, nil
}
func versionCount(ctx context.Context, api s3API, bucket, key string) (int, error) {
	out, err := api.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket), Prefix: aws.String(key)})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, v := range out.Versions {
		if v.Key != nil && *v.Key == key {
			count++
		}
	}
	return count, nil
}
