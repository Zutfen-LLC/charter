package evidence_test

import (
	"context"
	"sync"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

func TestC05ConcurrentBudgetClaimsCountBeforeDispatch(t *testing.T) {
	ctx := context.Background()
	db := testdb.New(t)
	st := store.Store{DB: db}
	tenant, err := st.CreateTenant(ctx, "issuer", "synthetic", "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	project, err := st.CreateProject(ctx, tenant, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	ledger := evidence.PG{DB: db}
	if err := ledger.SetPolicy(ctx, evidence.BudgetPolicy{TenantID: tenant, ProjectID: project, LocalOnly: true, AllowedModels: []string{"det-a"}, ProjectCap: 100}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, key := range []string{"one", "two"} {
		go func() {
			ready.Done()
			<-start
			_, err := ledger.Reserve(ctx, evidence.BudgetReservation{TenantID: tenant, ProjectID: project, TurnID: evidence.NewUUID(), IdempotencyKey: key, ModelID: "det-a", Destination: evidence.Destination{Provider: "synthetic", EndpointID: "local", ModelID: "a"}, Amount: 100})
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	var admitted int
	for range 2 {
		if err := <-results; err == nil {
			admitted++
		} else {
			t.Logf("reservation refused: %v", err)
		}
	}
	if admitted != 1 {
		t.Fatalf("want exactly one reservation before either dispatch, admitted=%d", admitted)
	}
}
