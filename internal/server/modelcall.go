package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/store"
)

const (
	maxCallBody  = 1 << 20
	maxArtifacts = 20
)

var keyRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// StubPolicy allows every turn to a fixed stub destination. Governed routing,
// budgets and model allow-lists arrive with #5; until then the destination
// identifiers recorded in evidence are these, never client-supplied.
func StubPolicy() func(context.Context, evidence.Request) (evidence.Decision, error) {
	return func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "stub-policy-0", ReserveUnits: 1000,
			Destination: evidence.Destination{Provider: "stub", EndpointID: "stub-local", ModelID: "stub-model-0"}}, nil
	}
}

// gateError is an authorization or deadline refusal at the release gate; it
// carries the HTTP status the caller must see.
type gateError struct {
	code int
	msg  string
}

func (e *gateError) Error() string { return e.msg }

type callBody struct {
	Input       string   `json:"input"`
	ArtifactIDs []string `json:"artifact_ids"`
}

// modelCall runs one governed turn. Evidence (ADR 0001 R1-R4) is written by
// evidence.Recorder.Process: admission, policy decision, sealed request bytes
// and disclosure intent are durable before the model is called; the output is
// durable and acknowledged before the release gate below runs; nothing is
// released if any required evidence write fails. Output is buffered, never
// streamed (pilot).
//
// The release gate keeps the guarantees introduced with #3, in this order:
//
//  1. If the work context is already done, release is refused (504/503).
//  2. ONE authoritative query "user active AND member of project" on committed
//     state, on its own context bounded by ReleaseCheckTimeout so cancelling the
//     request can neither abort the check into an implicit allow nor leave it
//     unbounded. Any failure returns no output.
//  3. The work context is checked again immediately before release, so an
//     expiry or cancellation during the query still prevents release.
//
// Work's deadline is COOPERATIVE (the handler cannot preempt it); the real
// execution bound belongs to the adapter (#5). What is guaranteed is that
// output produced after the deadline is never released. Whatever a model
// already received cannot be recalled; the evidence records that it was sent.
func (a *Auth) modelCall(w http.ResponseWriter, r *http.Request, p store.Principal) {
	pid := r.PathValue("pid")
	if a.Evidence == nil {
		a.Logf("model call refused: no evidence recorder configured")
		deny(w, http.StatusServiceUnavailable, "unavailable") // fail closed
		return
	}
	body, ok := a.readCallBody(w, r)
	if !ok {
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		key = evidence.NewUUID()
	} else if !keyRe.MatchString(key) {
		deny(w, http.StatusBadRequest, "invalid Idempotency-Key")
		return
	}
	matter, err := a.Store.ProjectMatter(r.Context(), p, pid)
	if err != nil {
		a.fail(w, err)
		return
	}
	var sources []evidence.Source
	seen := map[string]bool{}
	for _, id := range body.ArtifactIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		art, err := a.Store.GetArtifact(r.Context(), p, id)
		if err != nil || art.ProjectID != pid { // another project's artifact is "not found"
			deny(w, http.StatusNotFound, "not found")
			return
		}
		sources = append(sources, evidence.Source{ID: art.ID, Version: 1, Bytes: []byte(art.Body)})
	}
	pidC, _ := store.CanonicalID(pid)
	req := evidence.Request{TenantID: p.TenantID, ProjectID: pidC, MatterID: matter, CustodianID: p.UserID,
		IdempotencyKey: key, RequestID: evidence.NewUUID(), Input: []byte(body.Input), Sources: sources}

	ctx, cancel := context.WithTimeout(r.Context(), a.WorkTimeout)
	defer cancel()
	model := a.Model
	if model == nil {
		model = func(ctx context.Context, _ []byte) (evidence.ModelOutcome, error) {
			out, err := a.Work(ctx, p, pid)
			return evidence.ModelOutcome{Accepted: true, Complete: err == nil, Output: []byte(out)}, err
		}
	}
	gate := func(context.Context) error {
		if err := workContextErr(ctx); err != nil {
			return err
		}
		rc, rcancel := context.WithTimeout(context.Background(), a.ReleaseCheckTimeout)
		member, err := a.Store.IsMember(rc, p, pid) // includes the active-account predicate
		rcancel()
		if err != nil {
			a.Logf("model call release check: %v", err)
			return &gateError{http.StatusServiceUnavailable, "unavailable"}
		}
		if !member {
			return &gateError{http.StatusForbidden, "access revoked during request"}
		}
		return workContextErr(ctx) // final gate: expiry/cancellation during the query
	}
	res, err := a.Evidence.Process(ctx, req, model, gate)
	if err != nil {
		a.callError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": string(res.Output), "turn_id": res.TurnID, "replayed": res.Replayed})
}

func (a *Auth) readCallBody(w http.ResponseWriter, r *http.Request) (callBody, bool) {
	var b callBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCallBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil && !errors.Is(err, io.EOF) {
		deny(w, http.StatusBadRequest, "invalid request body")
		return b, false
	}
	if len(b.ArtifactIDs) > maxArtifacts {
		deny(w, http.StatusBadRequest, "too many artifact_ids")
		return b, false
	}
	return b, true
}

// callError maps a Process failure to a response. No branch ever writes model
// output; evidence failures are a generic 503.
func (a *Auth) callError(w http.ResponseWriter, err error) {
	var ge *gateError
	var ie *evidence.InterruptedError
	switch {
	case errors.As(err, &ge):
		deny(w, ge.code, ge.msg)
	case errors.Is(err, evidence.ErrDenied):
		deny(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, evidence.ErrIdempotencyMismatch):
		deny(w, http.StatusUnprocessableEntity, "idempotency key reused with different input")
	case errors.Is(err, evidence.ErrTurnInFlight):
		deny(w, http.StatusConflict, "a turn with this idempotency key is still in flight or awaiting recovery")
	case errors.As(err, &ie):
		deny(w, http.StatusConflict, "turn with this idempotency key was interrupted ("+ie.Disclosure+" disclosure); use a new Idempotency-Key to try again")
	case evidence.IsProviderError(err):
		a.fail(w, err) // provider failure: recorded; maps ErrNotFound/ErrForbidden, else 503
	default:
		a.Logf("model call: %v", err)
		deny(w, http.StatusServiceUnavailable, "unavailable")
	}
}

func workContextErr(ctx context.Context) error {
	switch cerr := ctx.Err(); {
	case cerr == nil:
		return nil
	case errors.Is(cerr, context.DeadlineExceeded):
		return &gateError{http.StatusGatewayTimeout, "work deadline exceeded"}
	default:
		return &gateError{http.StatusServiceUnavailable, "request cancelled"}
	}
}
