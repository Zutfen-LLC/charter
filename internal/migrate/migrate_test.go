package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Needs a Postgres reachable via CHARTER_TEST_DATABASE_URL (see scripts/dev.sh).
// The test works only inside a uniquely named schema that it creates and drops;
// it never touches other schemas or data in the database.
func TestUpIsIdempotent(t *testing.T) {
	url := os.Getenv("CHARTER_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CHARTER_TEST_DATABASE_URL not set; skipping DB test")
	}
	ctx := context.Background()

	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	schema := "charter_test_" + hex.EncodeToString(b[:]) // lowercase hex: safe as an identifier

	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		// Drops only the schema created above.
		if _, err := admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("cleanup of schema %s failed: %v", schema, err)
		}
	}()

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	first, err := Up(ctx, pool)
	if err != nil || len(first) == 0 {
		t.Fatalf("first run: %v %v", first, err)
	}
	second, err := Up(ctx, pool)
	if err != nil || len(second) != 0 {
		t.Fatalf("second run should be a no-op: %v %v", second, err)
	}
	var mode string
	if err := pool.QueryRow(ctx, `SELECT deployment_mode FROM instance`).Scan(&mode); err != nil || mode != "pilot-test" {
		t.Fatalf("instance row: %q %v", mode, err)
	}
	var n int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema=$1 AND table_name='instance'`, schema).Scan(&n); err != nil || n != 1 {
		t.Fatalf("instance table should live in %s: n=%d err=%v", schema, n, err)
	}
}
