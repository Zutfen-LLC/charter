package evidence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Fence is a single-instance ownership lock for the control plane: a
// PostgreSQL session-level advisory lock held on a dedicated connection for the
// life of the process. Crash recovery terminalizes every open turn admitted
// before it started, which is only correct if no OTHER live instance can be
// running turns, so recovery happens only while holding the fence. If the
// process dies the connection drops and the lock is released with it.
type Fence struct{ conn *pgx.Conn }

// ErrFenceHeld: another live instance holds the fence.
var ErrFenceHeld = errors.New("evidence: another control-plane instance holds the evidence fence")

// AcquireFence takes the fence without waiting. The key is scoped to the
// current schema so independent deployments sharing a server do not collide.
// The connection is taken out of the pool, so the lock can never be handed to
// other work or survive a Release.
func (b PG) AcquireFence(ctx context.Context) (*Fence, error) {
	c, err := b.DB.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	conn := c.Hijack()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended(current_schema() || ':charter-instance-fence', 0))`).Scan(&got); err != nil {
		_ = conn.Close(context.Background())
		return nil, err
	}
	if !got {
		_ = conn.Close(context.Background())
		return nil, ErrFenceHeld
	}
	return &Fence{conn: conn}, nil
}

// Release drops the lock by closing its dedicated connection.
func (f *Fence) Release() {
	if f != nil && f.conn != nil {
		_ = f.conn.Close(context.Background())
		f.conn = nil
	}
}
