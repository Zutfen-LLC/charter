package records

import (
	"context"
)

// ReconcileDueExports discovers tenants with expired package bytes or workers
// whose lease ended. Each actual transition is rechecked and audited under
// its own tenant lock by CleanupExports. Close enumeration before taking a
// new pooled connection, including with a single-connection pool.
func (s *Store) ReconcileDueExports(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT tenant_id::text FROM scoped_exports
  WHERE (expires_at IS NOT NULL AND expires_at<=clock_timestamp())
    OR (state='generating' AND lease_until<=clock_timestamp())
  ORDER BY tenant_id::text LIMIT 100`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := s.CleanupExports(ctx, id); err != nil {
			return err
		}
	}
	return nil
}
