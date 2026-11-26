package evidence

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Only a privilege refusal or our guard trigger counts as a refusal. Every
// other failure is inconclusive; a success is ALLOWED unless nothing was tested.
func TestClassifyOnlyCountsProtectionRefusals(t *testing.T) {
	pg := func(code, msg string) error { return &pgconn.PgError{Code: code, Message: msg} }
	for name, c := range map[string]struct {
		err  error
		rows int64
		dml  bool
		want Outcome
	}{
		"privilege refusal":  {pg("42501", "permission denied for table"), 0, true, Refused},
		"guard trigger":      {pg("P0001", "evidence_events is append-only evidence"), 0, true, Refused},
		"other raise":        {pg("P0001", "some other exception"), 0, true, Inconclusive},
		"undefined table":    {pg("42P01", "relation does not exist"), 0, true, Inconclusive},
		"unique violation":   {pg("23505", "duplicate"), 0, true, Inconclusive},
		"invalid uuid":       {pg("22P02", "invalid input syntax"), 0, true, Inconclusive},
		"statement timeout":  {pg("57014", "canceling statement due to statement timeout"), 0, true, Inconclusive},
		"connection failure": {errors.New("connection refused"), 0, true, Inconclusive},
		"succeeded":          {nil, 3, true, Allowed},
		"succeeded, no rows": {nil, 0, true, Inconclusive},
		"ddl succeeded":      {nil, 0, false, Allowed},
	} {
		if got, _ := classify(c.err, c.rows, c.dml); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
}
