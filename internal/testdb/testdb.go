// Package testdb gives tests an isolated, migrated schema in the database named
// by CHARTER_TEST_DATABASE_URL. It only ever creates and drops its own
// uniquely named charter_test_* schema.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/migrate"
	"github.com/jackc/pgx/v5/pgxpool"
)

// New returns a pool bound to a fresh migrated schema, or skips the test when
// no test database is configured.
func New(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("CHARTER_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CHARTER_TEST_DATABASE_URL not set; skipping DB test")
	}
	ctx := context.Background()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	schema := "charter_test_" + hex.EncodeToString(b[:])
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("cleanup of schema %s failed: %v", schema, err)
		}
		admin.Close()
	})
	if _, err := migrate.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}
