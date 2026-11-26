package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

func TestFenceShutdownDrainsHandlersBeforeRelease(t *testing.T) {
	owner := testdb.New(t)
	backend := evidence.PG{DB: owner}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f, err := backend.AcquireFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Release()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	serveCtx, stop := context.WithCancel(ctx)
	defer stop()
	entered, cancelled, resume := make(chan struct{}), make(chan struct{}), make(chan struct{})
	resumeHandler := resume
	defer func() {
		if resume != nil {
			close(resume)
		}
	}()
	done := make(chan error, 1)
	go func() {
		err := serveFencedHTTP(serveCtx, addr, f, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			close(entered)
			<-r.Context().Done()
			close(cancelled)
			<-resumeHandler
		}))
		f.Release()
		done <- err
	}()
	go func() {
		for ctx.Err() == nil {
			r, err := http.NewRequestWithContext(ctx, "GET", "http://"+addr, nil)
			if err != nil {
				return
			}
			resp, err := http.DefaultClient.Do(r)
			if err == nil {
				_ = resp.Body.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("server exited before entering handler: %v", err)
	case <-ctx.Done():
		t.Fatal("handler did not start")
	}
	stop()
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("in-flight context not cancelled")
	}
	if next, err := backend.AcquireFence(ctx); !errors.Is(err, evidence.ErrFenceHeld) {
		if next != nil {
			next.Release()
		}
		t.Fatalf("handoff occurred before handler exited: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("server exited before handler: %v", err)
	default:
	}
	close(resume)
	resume = nil
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("server did not exit after handler drained")
	}
	next, err := backend.AcquireFence(ctx)
	if err != nil {
		t.Fatalf("replacement did not acquire after drain: %v", err)
	}
	next.Release()
}
