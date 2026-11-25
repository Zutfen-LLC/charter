package evidence

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrFenceHeld = errors.New("evidence: another instance owns the fence or is still draining")
	ErrFenceLost = errors.New("evidence: instance ownership lost")
)

// Fence holds two session locks on independent, non-reconnecting connections.
// The original key is the ownership lock and the second is the drain barrier.
// Every new owner must acquire BOTH before it can recover. Thus the loss of
// either one session cannot by itself let a successor recover while the old
// owner can still finish a boundary-crossing operation. See docs/fence-ownership.md.
// The slot protects both pgx connections (which are not concurrency safe).
type Fence struct {
	primary, drain *pgx.Conn
	slot           chan struct{}
	lost           chan struct{}
}

const (
	ownershipKey = `SELECT pg_try_advisory_lock(hashtextextended(current_schema() || ':charter-instance-fence', 0))`
	drainKey     = `SELECT pg_try_advisory_lock(hashtextextended(current_schema() || ':charter-instance-drain', 0))`
	fenceTimeout = 2 * time.Second
)

// AcquireFence takes both locks without waiting on another owner. The sessions
// are removed from the pool and never replaced. Recovery is a startup-only
// operation and is run before starting HTTP handlers.
func (b PG) AcquireFence(ctx context.Context) (*Fence, error) {
	take := func(query string) (*pgx.Conn, error) {
		c, err := b.DB.Acquire(ctx)
		if err != nil {
			return nil, err
		}
		conn := c.Hijack()
		var got bool
		if err := conn.QueryRow(ctx, query).Scan(&got); err != nil {
			closeFenceConn(conn)
			return nil, err
		}
		if !got {
			closeFenceConn(conn)
			return nil, ErrFenceHeld
		}
		return conn, nil
	}
	primary, err := take(ownershipKey)
	if err != nil {
		return nil, err
	}
	drain, err := take(drainKey)
	if err != nil {
		closeFenceConn(primary)
		return nil, err
	}
	f := &Fence{primary: primary, drain: drain, slot: make(chan struct{}, 1), lost: make(chan struct{})}
	if err := f.Check(ctx); err != nil {
		f.Release()
		return nil, err
	}
	return f, nil
}

// Lost closes once, on a fatal serving transition; no code reacquires either
// session for this instance. Release also invalidates all subsequent use.
func (f *Fence) Lost() <-chan struct{} { return f.lost }

func (f *Fence) failLocked() {
	select {
	case <-f.lost:
	default:
		close(f.lost)
	}
}

// lease checks both sessions and lends the primary for one operation. Evidence
// transactions commit on that SAME PostgreSQL session: a different pool session
// cannot commit a stale owner's admission or recovery after the primary dies.
func (f *Fence) lease(ctx context.Context) (*pgx.Conn, func(), error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-f.lost:
		return nil, nil, ErrFenceLost
	case f.slot <- struct{}{}:
	}
	unlock := func() {
		if f.primary.IsClosed() || f.drain.IsClosed() {
			f.failLocked()
		}
		<-f.slot
	}
	select {
	case <-f.lost:
		unlock()
		return nil, nil, ErrFenceLost
	default:
	}
	// Probe cancellation is a failure of the bounded ownership check, not a
	// request cancellation. Do not run it on a caller's short-lived context.
	probe, cancel := context.WithTimeout(context.Background(), fenceTimeout)
	defer cancel()
	for _, conn := range []*pgx.Conn{f.primary, f.drain} {
		if err := conn.Ping(probe); err != nil {
			f.failLocked()
			unlock()
			return nil, nil, fmt.Errorf("%w: %v", ErrFenceLost, err)
		}
	}
	if err := ctx.Err(); err != nil {
		unlock()
		return nil, nil, err
	}
	return f.primary, unlock, nil
}

// Check is mandatory on dispatch and delivery (and inexpensive idle health
// monitoring). The check is not, by itself, a distributed synchronization lock.
// The drain barrier also excludes replacement recovery during single-session loss.
func (f *Fence) Check(ctx context.Context) error {
	if f == nil { // test/standalone recorders may use an unfenced backend
		return nil
	}
	_, unlock, err := f.lease(ctx)
	if err == nil {
		unlock()
	}
	return err
}

// Monitor detects idle session loss; boundary checks and PostgreSQL-owned writes
// do not rely on its cadence.
func (f *Fence) Monitor(ctx context.Context) {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.lost:
			return
		case <-tick.C:
			if f.Check(ctx) != nil {
				return
			}
		}
	}
}

// Release closes both sessions. The server calls it only after shutdown has
// joined its handlers; it never unlocks a live process to meet a timeout.
func (f *Fence) Release() {
	if f == nil {
		return
	}
	f.slot <- struct{}{}
	defer func() { <-f.slot }()
	f.failLocked()
	closeFenceConn(f.primary)
	closeFenceConn(f.drain)
}

func closeFenceConn(c *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), fenceTimeout)
	defer cancel()
	_ = c.Close(ctx)
}
