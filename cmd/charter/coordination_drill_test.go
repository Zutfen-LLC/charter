//go:build retention_drill

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/server"
)

func TestRetainedCoordinationAuthorityDrill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	c := config.Load()
	must(validateSyntheticDatabases(c))
	deps, err := openServing(ctx, c)
	must(err)
	defer deps.Close()
	pg := evidence.PG{DB: deps.Evidence}
	f, err := pg.AcquireFence(ctx)
	must(err)
	defer f.Release()
	b, _, err := connectRetained(ctx, c.Addr, c.RetentionS3, f)
	must(err)
	rec := &evidence.Recorder{Backend: b, Fence: f, Policy: server.StubPolicy()}
	req := evidence.Request{TenantID: "coordination-fixture", ProjectID: "project", MatterID: "matter", CustodianID: "custodian", IdempotencyKey: "coordination", RequestID: "coordination", Input: []byte("synthetic authority boundary")}
	var calls atomic.Int32
	model := func(context.Context, []byte) (evidence.ModelOutcome, error) {
		calls.Add(1)
		return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("never delivered by stale owner")}, nil
	}
	paused, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var result evidence.Result
	var processErr error
	go func() {
		defer close(done)
		result, processErr = rec.Process(ctx, req, model, func(context.Context) error {
			select {
			case <-paused:
				return nil
			default:
				close(paused)
				select {
				case <-resume:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		})
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-paused:
	case <-done:
		t.Fatalf("turn did not reach authorization barrier: %v", processErr)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	open, err := b.OpenTurns(ctx, time.Time{})
	must(err)
	if len(open) != 1 || open[0].TenantID != req.TenantID {
		t.Fatalf("expected one admitted turn paused at dispatch, got %v", open)
	}
	turn := open[0].TurnID
	before, err := b.Load(ctx, req.TenantID, turn)
	must(err)
	if len(before) < 2 || before[len(before)-2]["type"] != "disclosure_intent" || before[len(before)-1]["type"] != "evidence_ack" {
		t.Fatal("paused turn is not at durable pre-dispatch intent")
	}

	foreign := c
	foreign.DatabaseURL = os.Getenv("CHARTER_DRILL_FOREIGN_WORKSPACE_DSN")
	foreign.EvidenceDatabaseURL = os.Getenv("CHARTER_DRILL_FOREIGN_EVIDENCE_DSN")
	must(validateSyntheticDatabases(foreign))
	localDSN, err := labDSN(c.EvidenceDatabaseURL)
	must(err)
	foreignDSN, err := labDSN(foreign.EvidenceDatabaseURL)
	must(err)
	if localDSN.ConnConfig.Database == foreignDSN.ConnConfig.Database {
		t.Fatal("test requires distinct coordination databases")
	}
	foreignAddr := "127.0.0.1:0"
	trial, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	cmd := exec.CommandContext(trial, os.Getenv("CHARTER_DRILL_BINARY"), "serve")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	cmd.Env = []string{"CHARTER_DATABASE_URL=" + foreign.DatabaseURL, "CHARTER_EVIDENCE_DATABASE_URL=" + foreign.EvidenceDatabaseURL, "CHARTER_ADDR=" + foreignAddr, "CHARTER_EVIDENCE_BACKEND=s3-object-lock"}
	for _, row := range os.Environ() {
		if strings.HasPrefix(row, "CHARTER_S3_") {
			cmd.Env = append(cmd.Env, row)
		}
	}
	out, startErr := cmd.CombinedOutput()
	after, err := b.Load(ctx, req.TenantID, turn)
	must(err)
	t.Logf("foreign startup: %v; retained events before=%d after=%d; %s", startErr, len(before), len(after), out)
	if startErr == nil || trial.Err() != nil || !bytes.Contains(out, []byte("coordination authority mismatch")) || bytes.Contains(out, []byte("evidence recovery:")) || len(after) != len(before) {
		t.Fatal("foreign database was not refused before recovery and serving")
	}

	// Withdraw the original ownership before letting its stale handler cross
	// the outbound boundary, then restart on the original coordination DB.
	f.Release()
	close(resume)
	<-done
	if processErr == nil || calls.Load() != 0 || len(result.Output) != 0 {
		t.Fatalf("stale owner dispatched or delivered: calls=%d err=%v", calls.Load(), processErr)
	}
	next, err := pg.AcquireFence(ctx)
	must(err)
	b, _, err = connectRetained(ctx, c.Addr, c.RetentionS3, next)
	must(err)
	n, err := (&evidence.Recorder{Backend: b, Fence: next}).Recover(ctx, time.Time{})
	next.Release()
	if err != nil || n != 1 {
		t.Fatalf("rightful recovery: %d %v", n, err)
	}
	deps.Close()
	secret, err := os.ReadFile(c.RetentionS3.SecretFile)
	must(err)
	sc := c.RetentionS3
	s3, err := s3transport.New(s3transport.Config{Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket, AccessKeyID: sc.AccessKey, SecretAccessKey: strings.TrimSpace(string(secret))})
	must(err)
	key, err := hex.DecodeString(sc.CommitKey)
	must(err)
	view, err := evidence.NewRetentionBackend(evidence.RetentionOptions{Store: s3, Deployment: sc.Deployment, Bucket: sc.Bucket, TrustedCommitKey: key})
	must(err)
	events, err := view.Load(ctx, req.TenantID, turn)
	must(err)
	objects, err := view.LoadRetainedObjects(ctx, req.TenantID, turn, events)
	must(err)
	if len(events) <= len(before) || events[len(events)-1]["type"] != evidence.TypeTurnInterrupted || len(evidence.VerifyRetentionFull(events, objects)) != 0 {
		t.Fatal("database-independent reconstruction did not verify rightful recovery")
	}
	if _, err := view.PutObject(ctx, req.TenantID, []byte("read only")); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("independent view did not enforce read-only mode: %v", err)
	}
}
