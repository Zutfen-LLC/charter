package migrate

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Needs a disposable database: set CHARTER_TEST_DATABASE_URL (see scripts/dev.sh).
func TestUpIsIdempotent(t *testing.T) {
	url := os.Getenv("CHARTER_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CHARTER_TEST_DATABASE_URL not set; skipping DB test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// Start from a clean slate; the test database is disposable by contract.
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
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
}
