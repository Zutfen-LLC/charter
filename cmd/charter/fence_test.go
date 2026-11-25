package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

func TestServeExitsWhenOwnershipSessionTerminates(t *testing.T) {
	owner := testdb.New(t)
	c := testdb.Runtime(t, owner)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, config.Config{Addr: addr, DatabaseURL: c.WorkspaceURL, EvidenceDatabaseURL: c.EvidenceURL})
	}()
	wait := time.NewTimer(5 * time.Second)
	defer wait.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	ready := false
	for !ready {
		select {
		case err := <-done:
			t.Fatalf("server stopped before readiness: %v", err)
		case <-wait.C:
			t.Fatal("server never became ready")
		case <-tick.C:
			r, err := client.Get("http://" + addr + "/readyz")
			if err == nil {
				r.Body.Close()
				ready = r.StatusCode == http.StatusOK
			}
		}
	}
	var terminated bool
	err = owner.QueryRow(ctx, `WITH key AS (SELECT hashtextextended(current_schema() || ':charter-instance-fence', 0) AS v)
		SELECT pg_terminate_backend(l.pid, 3000) FROM pg_locks l, key
		JOIN pg_stat_activity a ON a.usename = $1
		WHERE a.pid = l.pid AND l.locktype = 'advisory' AND l.granted AND l.objsubid = 1
		AND l.classid::bigint = ((v >> 32) & 4294967295) AND l.objid::bigint = (v & 4294967295)`, c.EvidenceRole).Scan(&terminated)
	if err != nil || !terminated {
		t.Fatalf("did not terminate the actual fence session: %v, %v", terminated, err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("fence loss must be a fatal serving error")
		}
	case <-time.After(4 * time.Second):
		t.Error("server kept running after its actual ownership session terminated")
		cancel()
		<-done
	}
}
