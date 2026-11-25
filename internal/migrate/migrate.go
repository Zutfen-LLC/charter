// Package migrate applies embedded, ordered SQL migrations.
package migrate

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Zutfen-LLC/charter/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Up applies any migration not yet recorded, each in its own transaction.
// A advisory lock serializes concurrent runners.
func Up(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(7264001)`); err != nil {
		return nil, err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(7264001)`)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var applied []string
	for _, name := range names {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, name).Scan(&exists); err != nil {
			return applied, err
		}
		if exists {
			continue
		}
		sql, err := migrations.FS.ReadFile(name)
		if err != nil {
			return applied, err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return applied, err
		}
		if err := run(ctx, tx, name, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("migration %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, err
		}
		applied = append(applied, name)
	}
	return applied, nil
}

func run(ctx context.Context, tx pgx.Tx, name, sql string) error {
	if _, err := tx.Exec(ctx, sql); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, name)
	return err
}

// Pending lists embedded migrations that are not recorded as applied. It only
// reads schema_migrations, so the serving credential can use it to refuse to
// start against an unmigrated or older database without being able to migrate.
func Pending(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		have[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var pending []string
	for _, n := range names {
		if !have[n] {
			pending = append(pending, n)
		}
	}
	return pending, nil
}
