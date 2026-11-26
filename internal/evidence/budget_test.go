package evidence

import "testing"

func TestBudgetSafeAmountRejectsNegativeAndUnsafeIntegers(t *testing.T) {
	for _, amount := range []int64{-1, 1 << 53} {
		if safeBudgetAmount(amount) {
			t.Fatalf("accepted unsafe amount %d", amount)
		}
	}
	if !safeBudgetAmount(1<<53 - 1) {
		t.Fatal("rejected largest canonical safe integer")
	}
}
