package evidence

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	SchemaVersion = "1.0.0"
	// CurrentProfile is recorded on admission and covers the entire turn.
	CurrentProfile        = "charter-postgres-v1"
	RetentionProfile      = "charter-s3-compliance-v1"
	retentionDurableLevel = "s3:object-lock:COMPLIANCE"
)

// Keep the exact-storage recheck before last-mile authorization and fencing.
type retainedTurnVerifier interface {
	VerifyRetainedTurn(context.Context, string, string, []Event) error
}

type retainedTurnBackend interface {
	retainedTurnVerifier
	LoadRetainedObjects(context.Context, string, string, []Event) (map[string][]byte, error)
}

func (rc *Recorder) verifyRetained(ctx context.Context, t *turn, expected []Event) error {
	b, ok := rc.Backend.(retainedTurnVerifier)
	if !ok {
		return nil
	}
	c, cancel := context.WithTimeout(ctx, rc.EvidenceTimeout)
	defer cancel()
	return b.VerifyRetainedTurn(c, t.tenant, t.id, expected)
}

// Destination is where the policy decision routed the request: the ACTUAL
// provider endpoint and model identifier, not what the client asked for.
type Destination struct {
	Provider   string
	EndpointID string
	ModelID    string
}

// Decision is the policy outcome for one turn. Routing and budgets arrive with
// #5; this slice only records whatever decision it is given.
type Decision struct {
	Allow         bool
	Reason        string
	PolicyVersion string
	Destination   Destination
	ReserveUnits  int
}

// Source is one retrieved excerpt: the exact bytes placed in the context and
// the version they came from (ADR versioning rule 7).
type Source struct {
	ID       string
	Version  int
	Bytes    []byte
	External *ExternalSource
}

// Request is everything the recorder needs to admit one turn.
type Request struct {
	TenantID, ProjectID, MatterID, CustodianID string
	IdempotencyKey                             string
	RequestID                                  string
	ModelID                                    string // stable registry key, not a provider model override
	Input                                      []byte
	Sources                                    []Source
	// AuthorizeSources freshly verifies every external binding for the trusted serving principal.
	AuthorizeSources func(context.Context) error
}

// ModelOutcome is what an adapter reports. Accepted means the provider took
// the request (so disclosure happened) even if the call then failed; Complete
// means Output is the whole answer.
type ModelOutcome struct {
	Accepted bool
	Complete bool
	Output   []byte
	// UsageUnits is exact billable cost, when validated by the governed adapter.
	UsageUnits *int64
	// A lower bound, not an exact charge. UnquantifiedExposure records a
	// distinct incident for which no output-derived amount can be justified.
	ObservedOverrunFloor int64
	UnquantifiedExposure bool
}

// ModelFunc performs the outbound call with the exact sealed request bytes. It
// is only ever invoked after the disclosure intent is durably acknowledged.
type ModelFunc func(ctx context.Context, sent []byte) (ModelOutcome, error)

// Result of a processed turn. Output is set only when the turn completed and
// the output was durably recorded before release.
type Result struct {
	TurnID   string
	Output   []byte
	Replayed bool // an idempotent replay: stored output, no new model call
}

var (
	ErrDenied           = errors.New("evidence: policy denied the turn")
	ErrTurnInFlight     = errors.New("evidence: turn with this idempotency key is still in flight or awaiting recovery")
	ErrFailClosed       = errors.New("evidence: required evidence write failed; nothing was released")
	ErrFinalizeFailed   = errors.New("evidence: turn could not be finalized after release; recovery will complete it")
	ErrOutputUnreleased = errors.New("evidence: output recorded but not released")
)

// InterruptedError reports a replay of a turn that ended interrupted. It never
// triggers a new model call; the caller must submit a new idempotency key.
type InterruptedError struct{ TurnID, Reason, Disclosure string }

func (e *InterruptedError) Error() string {
	return fmt.Sprintf("evidence: turn %s was interrupted (%s, disclosure %s)", e.TurnID, e.Reason, e.Disclosure)
}

// SafeToResubmit reports whether nothing was disclosed, so a new request cannot
// duplicate a disclosure. With "unknown" or "disclosed" it is false: the
// operation may have happened and needs review (reconciliation), not a blind
// retry under a new key.
func (e *InterruptedError) SafeToResubmit() bool { return e.Disclosure == DisclosureNone }

// AbortedError is returned when the caller's context ended (cancelled or
// deadline) before dispatch or at delivery. Stage says where; Unwrap exposes
// context.Canceled / context.DeadlineExceeded. Evidence of what already
// happened is still recorded.
type AbortedError struct {
	Stage string
	Cause error
}

func (e *AbortedError) Error() string {
	return "evidence: aborted before " + e.Stage + ": " + e.Cause.Error()
}
func (e *AbortedError) Unwrap() error { return e.Cause }

// TurnLifecycleGuard enforces hold protection for new matching work (C07).
// HoldApplies is consulted with the turn's exact recorded time (its event 0);
// when a matching active hold exists, EnsureProtected must establish and
// verify storage-native protection for every version of the turn published
// so far before the turn may proceed. Any error fails the turn closed.
type TurnLifecycleGuard interface {
	HoldApplies(ctx context.Context, tenant, matter, custodian string, recordedAt time.Time) (bool, error)
	EnsureProtected(ctx context.Context, tenant, turn string) error
}

// Recorder is the durable write path. Its ordering enforces ADR 0001 R1-R4
// before each event is stored, and every step fails closed.
type Recorder struct {
	Backend Backend
	// Lifecycle, when configured, is the C07 hold guard: new matching work is
	// protected (and the protection verified) before anything is released,
	// so no successful response escapes without its required hold protection.
	Lifecycle TurnLifecycleGuard
	// Fence is required by the serving entrypoint. Its backend must be bound to
	// the same ownership session using PG.WithFence.
	Fence *Fence
	// Policy decides each turn. Required.
	Policy     func(ctx context.Context, r Request) (Decision, error)
	Governance Governance
	Accounting func(context.Context, Backend, string, string) error
	Clock      func() time.Time
	NewID      func() string
	// EvidenceTimeout bounds each evidence write. Writes use a context detached
	// from the caller's cancellation so a cancelled request can still record how
	// it ended.
	EvidenceTimeout time.Duration
	ServiceID       string
	Logf            func(string, ...any)

	once sync.Once // defaults are filled in exactly once; a Recorder is shared by concurrent requests
}

func (rc *Recorder) defaults() { rc.once.Do(rc.fillDefaults) }

func (rc *Recorder) fillDefaults() {
	if rc.Clock == nil {
		rc.Clock = time.Now
	}
	if rc.NewID == nil {
		rc.NewID = NewUUID
	}
	if rc.EvidenceTimeout == 0 {
		rc.EvidenceTimeout = 5 * time.Second
	}
	if rc.ServiceID == "" {
		rc.ServiceID = "charter-control-plane"
	}
	if rc.Logf == nil {
		rc.Logf = func(string, ...any) {}
	}
}

// NewUUID returns a random lowercase UUID (v4).
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // no entropy: nothing safe to do
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func ref(b []byte) map[string]any { return map[string]any{"sha256": SHA256(b), "bytes": len(b)} }

// RenderRequest builds the exact provider request bytes: canonical JSON of the
// model id, the user input and the sealed excerpts. The bytes it returns are
// what is stored and sent; nothing is re-rendered afterwards.
func RenderRequest(d Destination, input []byte, sources []Source) ([]byte, error) {
	ex := make([]any, 0, len(sources))
	for _, s := range sources {
		src := map[string]any{"source_id": s.ID, "text": string(s.Bytes)}
		if s.External == nil {
			src["version"] = s.Version
		} else {
			src["provider_version"] = s.External.ProviderVersion
		}
		ex = append(ex, src)
	}
	return Canonical(map[string]any{"model": d.ModelID, "input": string(input), "excerpts": ex})
}

// turn is the in-memory view of one log, always rebuilt from the backend after
// any failure so an ambiguous write is never assumed to have failed.
type turn struct {
	rc                   *Recorder
	tenant               string
	id                   string
	events               []Event
	observedOverrunFloor int64
	unquantifiedExposure bool
}

func (t *turn) lastHash() any {
	if len(t.events) == 0 {
		return nil
	}
	return t.events[len(t.events)-1]["event_hash"]
}

func (rc *Recorder) wctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), rc.EvidenceTimeout)
}

func (rc *Recorder) stamp() string { return rc.Clock().UTC().Format("2006-01-02T15:04:05.000Z") }

// build constructs the next sealed event of the turn.
func (t *turn) build(typ string, actor map[string]any, p map[string]any) (Event, error) {
	if err := screen(p); err != nil {
		return nil, err
	}
	first := t.events[0]
	e := Event{
		"schema_version": SchemaVersion,
		"tenant_id":      str(first, "tenant_id"), "project_id": str(first, "project_id"),
		"matter_id": str(first, "matter_id"), "turn_id": t.id,
		"seq": len(t.events), "type": typ, "recorded_at": t.rc.stamp(),
		"actor": actor, "payload": p, "prev_hash": t.lastHash(),
	}
	return e, Seal(e)
}

func (t *turn) svc() map[string]any {
	return map[string]any{"kind": "service", "id": t.rc.ServiceID}
}

// emit stores one event and, only on success, extends the in-memory chain.
func (t *turn) emit(ctx context.Context, typ string, p map[string]any) (Event, Receipt, error) {
	e, err := t.build(typ, t.svc(), p)
	if err != nil {
		return nil, Receipt{}, err
	}
	wc, cancel := t.rc.wctx(ctx)
	defer cancel()
	r, err := t.rc.Backend.Append(wc, e)
	if err != nil {
		return nil, Receipt{}, err
	}
	t.events = append(t.events, e)
	return e, r, nil
}

// ack stores an evidence_ack for the last event. Only after it returns nil may
// the gate it guards open (R1, R2).
func (t *turn) ack(ctx context.Context, r Receipt) error {
	last := t.events[len(t.events)-1]
	p := map[string]any{
		"acked_seq": last["seq"], "acked_event_hash": last["event_hash"],
		"receipt": r.ID, "storage_level": r.Level}
	if _, ok := t.rc.Backend.(retainedTurnBackend); ok {
		if r.Retained == nil || r.Level != retentionDurableLevel {
			return ErrNotDurable
		}
		id, err := retainedReceiptID(*r.Retained)
		if err != nil || id != r.ID || r.Retained.EventHash != str(last, "event_hash") {
			return ErrNotDurable
		}
		p["retained_receipt"] = mapRetainedReceipt(*r.Retained)
	}
	_, _, err := t.emit(ctx, "evidence_ack", p)
	return err
}

// emitAcked stores an event, then its acknowledgment.
func (t *turn) emitAcked(ctx context.Context, typ string, p map[string]any) error {
	_, r, err := t.emit(ctx, typ, p)
	if err != nil {
		return err
	}
	return t.ack(ctx, r)
}

func (rc *Recorder) put(ctx context.Context, tenant string, data []byte) error {
	wc, cancel := rc.wctx(ctx)
	defer cancel()
	_, err := rc.Backend.PutObject(wc, tenant, data)
	return err
}

// Process runs one turn through the full evidence path.
//
//  1. Admission is durable (turn row + turn_received + exact input) before any
//     policy or dispatch work; a repeated idempotency key never re-dispatches.
//  2. policy_decision, usage_reserved, context_sealed (exact request bytes and
//     source versions), disclosure_intent and its ack are durable BEFORE the
//     model is called (R1).
//  3. The output (partial or complete) is stored and acknowledged before
//     anything is returned (R2); the output is buffered, never streamed.
//  4. gate runs after the output ack and may veto the release (authorization
//     re-check). A veto records turn_interrupted and releases nothing.
//  5. Any evidence failure at any step: nothing is released and the turn is
//     marked interrupted (or left for recovery if even that cannot be stored).
func (rc *Recorder) Process(ctx context.Context, req Request, call ModelFunc, gate func(context.Context) error) (Result, error) {
	rc.defaults()
	if rc.Backend == nil || (rc.Governance == nil && (rc.Policy == nil || call == nil)) {
		return Result{}, fmt.Errorf("%w: recorder is not configured", ErrFailClosed)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, &AbortedError{Stage: "admission", Cause: err}
	}
	if _, retained := rc.Backend.(retainedTurnBackend); (retained || rc.Governance != nil) && gate == nil {
		return Result{}, fmt.Errorf("%w: retained and governed turns require fresh authorization", ErrFailClosed)
	}
	if err := rc.Fence.Check(ctx); err != nil {
		return Result{}, err
	}
	if req.external() {
		if req.AuthorizeSources == nil || rc.Governance == nil || rc.Accounting == nil {
			return Result{}, fmt.Errorf("%w: external context requires source authorization and governed accounting", ErrFailClosed)
		}
		membership := gate
		gate = func(ctx context.Context) error {
			return req.checkAccess(ctx, membership)
		}
	}
	t, replay, err := rc.admit(ctx, req)
	if err != nil {
		return Result{}, err
	}
	if replay != nil {
		return rc.replay(ctx, t, req, gate)
	}
	return rc.run(ctx, t, req, call, gate)
}

func (rc *Recorder) admit(ctx context.Context, req Request) (*turn, *struct{}, error) {
	if req.IdempotencyKey == "" {
		return nil, nil, errors.New("evidence: idempotency key required")
	}
	id := rc.NewID()
	fp, err := Fingerprint(req)
	if err != nil {
		return nil, nil, err
	}
	profile := CurrentProfile
	if _, ok := rc.Backend.(retainedTurnBackend); ok {
		profile = RetentionProfile
	}
	first := Event{
		"schema_version": SchemaVersion, "tenant_id": req.TenantID, "project_id": req.ProjectID,
		"matter_id": req.MatterID, "turn_id": id, "seq": 0, "type": "turn_received",
		"recorded_at": rc.stamp(), "actor": map[string]any{"kind": "user", "id": req.CustodianID},
		"payload": map[string]any{"request_id": req.RequestID, "input": ref(req.Input),
			"evidence_profile": profile, "custodian_id": req.CustodianID,
			"objects": []any{ref(req.Input)}, "request_fingerprint": fp},
		"prev_hash": nil,
	}
	if req.external() {
		p := payload(first)
		p["source_binding_version"] = 1
		if req.ModelID != "" {
			p["model_registry_id"] = req.ModelID
		}
	}
	if err := Seal(first); err != nil {
		return nil, nil, err
	}
	wc, cancel := rc.wctx(ctx)
	defer cancel()
	res, err := rc.Backend.Admit(wc, Admission{TenantID: req.TenantID, ProjectID: req.ProjectID,
		MatterID: req.MatterID, CustodianID: req.CustodianID, IdempotencyKey: req.IdempotencyKey,
		TurnID: id, Fingerprint: fp}, first, [][]byte{req.Input})
	if err != nil {
		if errors.Is(err, ErrIdempotencyMismatch) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("%w: admission: %v", ErrFailClosed, err)
	}
	if !res.Created {
		return &turn{rc: rc, tenant: req.TenantID, id: res.TurnID}, &struct{}{}, nil
	}
	if rc.Lifecycle != nil {
		if err := rc.ensureProtected(wc, req, id, first); err != nil {
			return nil, nil, fmt.Errorf("%w: admission hold protection: %w", ErrFailClosed, err)
		}
	}
	return &turn{rc: rc, tenant: req.TenantID, id: id, events: []Event{first}}, nil, nil
}

// ensureProtected fails the turn closed unless a matching active hold's
// storage-native protection is established and verified for the turn.
func (rc *Recorder) ensureProtected(ctx context.Context, req Request, turnID string, first Event) error {
	recorded, err := time.Parse(time.RFC3339Nano, str(first, "recorded_at"))
	if err != nil {
		return err
	}
	applies, err := rc.Lifecycle.HoldApplies(ctx, req.TenantID, req.MatterID, req.CustodianID, recorded)
	if err != nil || !applies {
		return err
	}
	return rc.Lifecycle.EnsureProtected(ctx, req.TenantID, turnID)
}

// EnsureTurnProtected re-checks hold protection immediately before release
// (the release gate) and before a replay delivery, using the stored event-0
// identity of the turn. It is a no-op when no lifecycle guard is configured.
func (rc *Recorder) EnsureTurnProtected(ctx context.Context, t *turn) error {
	if rc.Lifecycle == nil || len(t.events) == 0 {
		return nil
	}
	wc, cancel := rc.wctx(ctx)
	defer cancel()
	first := t.events[0]
	req := Request{TenantID: str(first, "tenant_id"), MatterID: str(first, "matter_id"), CustodianID: str(actorOf(first), "id")}
	return rc.ensureProtected(wc, req, t.id, first)
}

// replay answers a repeated idempotency key from the log only. It never
// dispatches. Before returning anything it validates the stored evidence: the
// log must verify, belong to this exact request, and the output object must
// match what the log recorded. Anything missing, malformed or inconsistent
// fails closed. A completed turn's output is still subject to the caller's
// delivery gate (delivery-only retry stays authorized).
func (rc *Recorder) replay(ctx context.Context, t *turn, req Request, gate func(context.Context) error) (Result, error) {
	wc, cancel := rc.wctx(ctx)
	defer cancel()
	bad := func(format string, a ...any) (Result, error) {
		return Result{}, fmt.Errorf("%w: replay: %s", ErrFailClosed, fmt.Sprintf(format, a...))
	}
	evs, err := rc.Backend.Load(wc, t.tenant, t.id)
	if err != nil {
		return bad("load: %v", err)
	}
	if len(evs) == 0 {
		return bad("empty stored log")
	}
	t.events = evs
	lastEv := evs[len(evs)-1]
	if !isTerminal(str(lastEv, "type")) {
		return Result{}, ErrTurnInFlight
	}
	var objs map[string][]byte
	retained, retainedProfile := rc.Backend.(retainedTurnBackend)
	if retainedProfile {
		if str(payload(evs[0]), "evidence_profile") != RetentionProfile {
			return bad("required retention profile missing")
		}
		objs, err = retained.LoadRetainedObjects(wc, t.tenant, t.id, evs)
	} else {
		if str(payload(evs[0]), "evidence_profile") == RetentionProfile {
			return bad("retention profile cannot be verified on this backend")
		}
		objs, err = loadObjects(wc, rc.Backend, t.tenant, evs)
	}
	if err != nil {
		return bad("%v", err)
	}
	if errs := Verify(evs, objs); len(errs) != 0 {
		return bad("stored evidence does not verify: %s", strings.Join(errs, "; "))
	}
	fp, err := Fingerprint(req)
	first := evs[0]
	if err != nil || payload(first)["request_fingerprint"] != fp || str(first, "tenant_id") != req.TenantID ||
		str(first, "project_id") != req.ProjectID || str(first, "matter_id") != req.MatterID ||
		str(actorOf(first), "id") != req.CustodianID {
		return bad("stored turn does not match this request")
	}
	if str(lastEv, "type") == TypeTurnInterrupted {
		return Result{}, &InterruptedError{TurnID: t.id, Reason: str(payload(lastEv), "reason"), Disclosure: DeriveDisclosure(evs)}
	}
	// Even historical logs may be replayed only if their exact original input
	// matches this request. A summary and a matching identity are not enough.
	if input, ok := asRef(payload(first)["input"]); !ok || input.sha != SHA256(req.Input) || input.bytes != int64(len(req.Input)) {
		return bad("stored input does not match exact original bytes")
	}
	if payload(lastEv)["outcome"] == "denied" {
		return Result{}, ErrDenied
	}
	i := last(evs, "output_recorded")
	if i < 0 || payload(evs[i])["complete"] != true {
		return bad("completed turn has no complete output")
	}
	refs, _ := payload(evs[i])["objects"].([]any)
	if len(refs) != 1 {
		return bad("output must be exactly one object")
	}
	m, _ := refs[0].(map[string]any)
	sha, _ := m["sha256"].(string)
	out, ok := objs[sha]
	if !ok {
		return bad("output object missing")
	}
	if n, _ := integer(m["bytes"]); n != int64(len(out)) || SHA256(out) != sha {
		return bad("output object does not match its record")
	}
	if err := rc.verifyRetained(ctx, t, evs); err != nil {
		return bad("retained readback: %v", err)
	}
	if retainedProfile && gate == nil {
		return bad("fresh delivery authorization is required")
	}
	if err := rc.reconcile(ctx, t); err != nil {
		return bad("budget reconciliation pending")
	}
	if err := rc.EnsureTurnProtected(ctx, t); err != nil {
		return bad("hold protection: %v", err)
	}
	if err := rc.finalGate(ctx, gate, "delivery"); err != nil {
		return Result{}, err
	}
	return Result{TurnID: t.id, Output: out, Replayed: true}, nil
}

func actorOf(e Event) map[string]any { a, _ := e["actor"].(map[string]any); return a }

// loadObjects fetches every object an event log references.
func loadObjects(ctx context.Context, b Backend, tenant string, evs []Event) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, e := range evs {
		for _, r := range objectRefs(e) {
			if _, ok := out[r]; ok {
				continue
			}
			data, err := b.Object(ctx, tenant, r)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					continue // reported by Verify as a missing object
				}
				return nil, fmt.Errorf("load object %s: %w", r, err)
			}
			out[r] = data
		}
	}
	return out, nil
}

// finalGate is the delivery-time check: the caller's context must still be live
// and the caller's fresh authorization check must pass. It runs AFTER every
// evidence write, immediately before output is handed back, so no database
// write, retry or settlement can sit between the last check and delivery.
func (rc *Recorder) finalGate(ctx context.Context, gate func(context.Context) error, stage string) error {
	if gate != nil {
		if err := gate(ctx); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return &AbortedError{Stage: stage, Cause: err}
	}
	return rc.Fence.Check(ctx)
}

func (rc *Recorder) run(ctx context.Context, t *turn, req Request, call ModelFunc, gate func(context.Context) error) (Result, error) {
	external := req.external()
	reconciled := false
	defer func() {
		if rc.Accounting != nil && !reconciled {
			if err := rc.reconcile(ctx, t); err != nil {
				rc.Logf("budget: turn remains pending reconciliation")
			}
		}
	}()
	fail := func(reason string, err error) (Result, error) {
		rc.abort(ctx, t, reason)
		return Result{}, fmt.Errorf("%w: %s: %v", ErrFailClosed, reason, err)
	}
	if err := ctx.Err(); err != nil { // admitted, but the caller is already gone: no policy work, no dispatch
		rc.abort(ctx, t, "cancelled_before_dispatch")
		return Result{}, &AbortedError{Stage: "policy", Cause: err}
	}
	var d Decision
	var plan GovernedPlan
	var sent []byte
	var err error
	if rc.Governance == nil {
		d, err = rc.Policy(ctx, req)
	} else {
		plan, err = rc.Governance(ctx, req)
		if err == nil && !plan.configured() {
			return fail("policy_error", errors.New("invalid governed plan"))
		}
		if err == nil {
			if external {
				// C06 context eligibility: revalidate delegated source
				// authorization and membership BEFORE any source-derived
				// request construction, object persistence or context
				// sealing, so a source that is revoked or unavailable after
				// selection can never become sealed model context. The
				// admission event remains lawfully captured evidence of the
				// request; the never-eligible context is never built.
				if gerr := gate(ctx); gerr != nil {
					rc.abort(ctx, t, "context_eligibility_denied")
					return Result{}, gerr
				}
			}
			sent, err = plan.Build(req)
			if err != nil {
				return fail("render_failed", err)
			}
			var reserved int
			reserved, err = plan.Reserve(ctx, t.id, sent)
			if err == nil {
				d = Decision{Allow: true, PolicyVersion: plan.PolicyVersion, Destination: plan.Destination, ReserveUnits: reserved}
				call = plan.Invoke
			} else if !errors.Is(err, ErrDenied) {
				// The transaction may have committed. Recovery must inspect the
				// durable reservation; this attempt must never use it to dispatch.
				return fail("reservation_unconfirmed", err)
			}
		}
	}
	if err != nil {
		// A policy evaluation failure is a durable denial, never an implicit
		// allow or a retryable open turn. Recovery recognizes this decision too.
		if _, _, writeErr := t.emit(ctx, "policy_decision", map[string]any{
			"decision": "deny", "reason": "policy_evaluation_failed", "policy_version": "unavailable",
		}); writeErr != nil {
			rc.abort(ctx, t, "policy_error")
			return Result{}, fmt.Errorf("%w: policy_error: %v (denial evidence: %v)", ErrFailClosed, err, writeErr)
		}
		if _, _, writeErr := t.emit(ctx, TypeTurnCompleted, map[string]any{"outcome": "denied"}); writeErr != nil {
			rc.abort(ctx, t, "policy_error")
			return Result{}, fmt.Errorf("%w: policy_error terminal: %v", ErrFailClosed, writeErr)
		}
		return Result{}, fmt.Errorf("%w: policy evaluation failed: %v", ErrDenied, err)
	}
	if !d.Allow {
		pd := map[string]any{"decision": "deny", "reason": d.Reason, "policy_version": d.PolicyVersion}
		if _, _, err := t.emit(ctx, "policy_decision", pd); err != nil {
			return fail("evidence_write_failed", err)
		}
		if _, _, err := t.emit(ctx, TypeTurnCompleted, map[string]any{"outcome": "denied"}); err != nil {
			return fail("evidence_write_failed", err)
		}
		return Result{}, ErrDenied
	}
	dest := map[string]any{"provider": d.Destination.Provider, "endpoint_id": d.Destination.EndpointID, "model_id": d.Destination.ModelID}
	if _, _, err := t.emit(ctx, "policy_decision", map[string]any{"decision": "allow", "route": d.Destination.EndpointID,
		"policy_version": d.PolicyVersion, "destination": dest}); err != nil {
		return fail("evidence_write_failed", err)
	}
	reservation := map[string]any{"units": d.ReserveUnits}
	if rc.Governance != nil {
		reservation["accounting_version"] = budgetVersion
		reservation["registry_model"] = plan.RegistryModel
	}
	if _, _, err := t.emit(ctx, "usage_reserved", reservation); err != nil {
		return fail("evidence_write_failed", err)
	}
	if rc.Governance == nil {
		sent, err = RenderRequest(d.Destination, req.Input, req.Sources)
		if err != nil {
			return fail("render_failed", err)
		}
	}
	objects := []any{}
	sources := []any{}
	for _, s := range req.Sources {
		if err := rc.put(ctx, t.tenant, s.Bytes); err != nil {
			return fail("evidence_write_failed", err)
		}
		objects = append(objects, ref(s.Bytes))
		sources = append(sources, s.descriptor(external, true))
	}
	if err := rc.put(ctx, t.tenant, sent); err != nil {
		return fail("evidence_write_failed", err)
	}
	objects = append(objects, ref(sent))
	if _, _, err := t.emit(ctx, "context_sealed", map[string]any{"sources": sources, "objects": objects,
		"request_sha256": SHA256(sent)}); err != nil {
		return fail("evidence_write_failed", err)
	}
	// R1: the intent, naming the exact request bytes and the actual destination,
	// must be durable and acknowledged before the model call below.
	intent := map[string]any{"provider": d.Destination.Provider,
		"endpoint_id": d.Destination.EndpointID, "model_id": d.Destination.ModelID, "request": ref(sent)}
	var provenance, dispatchAuthorization string
	if external {
		canonical, err := Canonical(sources)
		if err != nil {
			return fail("source_binding_failed", err)
		}
		provenance = SHA256(canonical)
		if err := gate(ctx); err != nil {
			rc.abort(ctx, t, "dispatch_denied")
			return Result{}, err
		}
		intent["source_authorized_at"] = rc.stamp()
	}
	if err := t.emitAcked(ctx, "disclosure_intent", intent); err != nil {
		return fail("evidence_write_failed", err)
	}
	if err := rc.verifyRetained(ctx, t, t.events); err != nil {
		return fail("retained_readback_failed", err)
	}
	if external {
		if _, retained := rc.Backend.(retainedTurnBackend); !retained {
			wc, done := rc.wctx(ctx)
			objects, err := loadObjects(wc, rc.Backend, t.tenant, t.events)
			done()
			if err != nil || len(verifyChain(t.events, objects, true, true)) != 0 {
				return fail("source_binding_failed", errors.New("source evidence readback failed"))
			}
		}
	}
	if rc.Governance != nil {
		if err := plan.Arm(ctx, t.id); err != nil {
			return fail("dispatch_arm_unconfirmed", err)
		}
	}
	if _, retained := rc.Backend.(retainedTurnBackend); (retained || rc.Governance != nil) && gate != nil {
		// Final delegated source authorization: sequential connector
		// metadata/read/metadata operations that can materially extend the
		// interval since the last local check.
		if err := gate(ctx); err != nil {
			rc.abort(ctx, t, "dispatch_denied")
			return Result{}, err
		}
		if external {
			dispatchAuthorization = rc.stamp()
		}
	}
	if rc.Governance != nil {
		// C05/C06 route authorization is re-resolved AFTER the final
		// delegated source revalidation above and as close to actual
		// invocation as practicable: only local checks (caller liveness and
		// the ownership fence) sit between this verification and the call.
		// Invoke itself does not resolve route authorization, so a policy
		// change committed during the connector operations must be seen
		// here, never at the model.
		if err := plan.CheckRoute(ctx); err != nil {
			rc.abort(ctx, t, "route_revoked_before_dispatch")
			return Result{}, err
		}
	}

	// Cancellation or expiry while the evidence above was being written: do not
	// dispatch. The acknowledged intent derives "unknown", which over-reports
	// (nothing was sent) and is the safe direction.
	if err := ctx.Err(); err != nil {
		rc.abort(ctx, t, "cancelled_before_dispatch")
		return Result{}, &AbortedError{Stage: "dispatch", Cause: err}
	}
	if err := rc.Fence.Check(ctx); err != nil {
		return fail("dispatch_ownership_lost", err)
	}
	out, callErr := call(ctx, sent) // the only outbound call
	if rc.Governance != nil {
		t.observedOverrunFloor = out.ObservedOverrunFloor
		t.unquantifiedExposure = out.UnquantifiedExposure
	}
	// Only a confirmed adapter acceptance is evidence of disclosure. An
	// adapter can return buffered bytes after an ambiguous failure; preserve
	// them as partial, but do not invent an acceptance or authorize release.
	if out.Accepted {
		accepted := map[string]any{"provider": d.Destination.Provider, "endpoint_id": d.Destination.EndpointID, "model_id": d.Destination.ModelID}
		if external {
			accepted["source_authorized_at"] = dispatchAuthorization
		}
		if _, _, err := t.emit(ctx, "provider_accepted", accepted); err != nil {
			return fail("evidence_write_failed", err)
		}
	}
	complete := out.Accepted && callErr == nil && out.Complete && t.observedOverrunFloor == 0 && !t.unquantifiedExposure
	if len(out.Output) > 0 || complete || (rc.Governance != nil && out.Accepted && out.UsageUnits != nil) {
		if err := rc.put(ctx, t.tenant, out.Output); err != nil {
			return fail("evidence_write_failed", err)
		}
		p := map[string]any{"complete": complete, "objects": []any{ref(out.Output)}}
		if external {
			p["source_provenance_sha256"] = provenance
		}
		if rc.Governance != nil && out.Accepted && out.UsageUnits != nil && safeBudgetAmount(*out.UsageUnits) {
			p["provider_cost_units"] = *out.UsageUnits
		}
		if err := t.emitAcked(ctx, "output_recorded", p); err != nil {
			return fail("evidence_write_failed", err)
		}
	}
	if !complete {
		reason := "provider_stream_error"
		if !out.Accepted {
			reason = "provider_error"
			if len(out.Output) > 0 || out.Complete {
				reason = "provider_acceptance_unconfirmed"
			}
		}
		rc.abort(ctx, t, reason)
		if callErr == nil {
			if !out.Accepted {
				callErr = errors.New("adapter did not confirm provider acceptance")
			} else {
				callErr = errors.New("provider returned an incomplete response")
			}
		}
		return Result{}, fmt.Errorf("%w: %w", errProvider, callErr)
	}

	// Release gate: output is durable; the caller may still veto the release.
	// Hold protection (C07) is verified here, after the last evidence write
	// and before release authorization: a hold that committed while this turn
	// was in flight is seen now, and its protection is established before any
	// output can escape.
	if err := rc.EnsureTurnProtected(ctx, t); err != nil {
		rc.abort(ctx, t, "hold_protection_failed")
		return Result{}, fmt.Errorf("%w: release hold protection: %w", ErrFailClosed, err)
	}
	if err := rc.verifyRetained(ctx, t, t.events); err != nil {
		return fail("retained_readback_failed", err)
	}
	if gate != nil {
		if err := gate(ctx); err != nil {
			rc.abort(ctx, t, "release_denied")
			return Result{}, err
		}
	}
	release := map[string]any{}
	if external {
		release["source_provenance_sha256"] = provenance
		release["source_authorized_at"] = rc.stamp()
	}
	if _, _, err := t.emit(ctx, "response_released", release); err != nil {
		rc.abort(ctx, t, "evidence_write_failed")
		return Result{}, fmt.Errorf("%w: release record: %v", ErrFailClosed, err)
	}
	// Past this point the log says "released", so it must end completed (R3).
	// Retry; if it still cannot be stored, recovery completes it. The output is
	// withheld from the caller either way.
	if err := rc.finish(ctx, t, d.ReserveUnits); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrFinalizeFailed, err)
	}
	// Delivery gate: re-authorize and re-check the context AFTER finalization.
	// If it refuses, the log still says the release was authorized and the turn
	// completed (the output is durable and a delivery-only retry stays possible
	// through replay), but this call returns no output.
	// Hold protection (C07) is verified here a second time, after the LAST
	// evidence write of the turn (the terminal event): every version the
	// response's evidence names is protected and verified before any output
	// escapes.
	if err := rc.EnsureTurnProtected(ctx, t); err != nil {
		return Result{TurnID: t.id}, fmt.Errorf("%w: delivery hold protection: %w", ErrFailClosed, err)
	}
	if err := rc.verifyRetained(ctx, t, t.events); err != nil {
		return fail("retained_readback_failed", err)
	}
	if err := rc.reconcile(ctx, t); err != nil {
		return Result{}, fmt.Errorf("%w: budget reconciliation pending", ErrFinalizeFailed)
	}
	reconciled = true
	if err := rc.finalGate(ctx, gate, "delivery"); err != nil {
		return Result{TurnID: t.id}, err
	}
	return Result{TurnID: t.id, Output: out.Output}, nil
}

var errProvider = errors.New("provider call failed")

// IsProviderError reports whether err is a model/provider failure (as opposed
// to an evidence failure). The failure has been recorded; nothing was released.
func IsProviderError(err error) bool { return errors.Is(err, errProvider) }

func (rc *Recorder) finish(ctx context.Context, t *turn, reserved int) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			if t.reload(ctx) != nil {
				continue
			}
		}
		if last := t.events[len(t.events)-1]; str(last, "type") == TypeTurnCompleted {
			return nil
		}
		if last(t.events, "usage_settled") < 0 {
			if _, _, err = t.emit(ctx, "usage_settled", settlementPayload(t.events, reserved)); err != nil {
				continue
			}
		}
		if _, _, err = t.emit(ctx, TypeTurnCompleted, map[string]any{"outcome": "completed"}); err == nil {
			return nil
		}
	}
	if err == nil {
		err = errors.New("could not reload turn")
	}
	return err
}

func (t *turn) reload(ctx context.Context) error {
	wc, cancel := t.rc.wctx(ctx)
	defer cancel()
	evs, err := t.rc.Backend.Load(wc, t.tenant, t.id)
	if err != nil {
		return err
	}
	t.events = evs
	return nil
}

// abort best-effort ends a non-terminal turn as interrupted with the
// disclosure state derived from what is durably stored. If the store is
// unavailable the turn stays open and Recover resolves it later; it is never
// left looking safe: disclosure is derived from the log, not from this call.
func (rc *Recorder) abort(ctx context.Context, t *turn, reason string) {
	if err := rc.resolve(ctx, t, reason); err != nil {
		rc.Logf("evidence: turn %s left open for recovery (%s): %v", t.id, reason, err)
	}
}

// resolve closes a turn. Shared by the live abort path and crash recovery. If
// it loses a race with another resolver (a live request vs. recovery, or two
// recoveries) the turn is terminal by the time it looks again, which is success:
// the database allows exactly one terminal event.
func (rc *Recorder) resolve(ctx context.Context, t *turn, reason string) error {
	err := rc.resolveOnce(ctx, t, reason)
	if err != nil && (errors.Is(err, ErrConflict) || errors.Is(err, ErrTerminal)) {
		if t.reload(ctx) == nil && isTerminal(str(t.events[len(t.events)-1], "type")) {
			return nil
		}
	}
	return err
}

func (rc *Recorder) resolveOnce(ctx context.Context, t *turn, reason string) error {
	if err := t.reload(ctx); err != nil {
		return err
	}
	lastEv := t.events[len(t.events)-1]
	if isTerminal(str(lastEv, "type")) {
		return nil
	}
	if i := last(t.events, "policy_decision"); i >= 0 && payload(t.events[i])["decision"] == "deny" {
		_, _, err := t.emit(ctx, TypeTurnCompleted, map[string]any{"outcome": "denied"})
		if errors.Is(err, ErrTerminal) {
			return nil
		}
		return err
	}
	if last(t.events, "response_released") >= 0 {
		// Already recorded as released: R3 requires it to complete.
		return rc.finish(ctx, t, reservedUnits(t.events))
	}
	disc := DeriveDisclosure(t.events)
	if disc != DisclosureNone && last(t.events, "usage_settled") < 0 {
		// This evidence is independent of the output object and also carries
		// the incident if the coordination write did not acknowledge it.
		p := interruptedSettlement(t.events, reason)
		if t.observedOverrunFloor > 0 {
			p["observed_overrun_floor"] = t.observedOverrunFloor
			if p["basis"] != "provider_reported" {
				p["basis"], p["units"] = "observed_minimum", t.observedOverrunFloor
			}
		}
		if t.unquantifiedExposure {
			p["unquantified_exposure"] = true
		}
		if _, _, err := t.emit(ctx, "usage_settled", p); err != nil {
			return err
		}
	}
	if i := last(t.events, "usage_settled"); i >= 0 {
		if saved := str(payload(t.events[i]), "confirmed_no_dispatch"); noDispatchReason(saved) {
			reason = saved
		}
	}
	_, _, err := t.emit(ctx, TypeTurnInterrupted, map[string]any{"reason": reason, "disclosure": disc})
	if errors.Is(err, ErrTerminal) {
		return nil // someone else (live path vs recovery) already ended it
	}
	return err
}

func reservedUnits(evs []Event) int {
	if i := last(evs, "usage_reserved"); i >= 0 {
		if n, ok := integer(payload(evs[i])["units"]); ok {
			return int(n)
		}
	}
	return 0
}

// Recover resolves every turn that has no terminal event and was admitted
// before the cutoff (zero means no cutoff): it appends turn_interrupted (reason crash_recovery) with
// the disclosure derived from the log, as the service, never as the user. A
// turn whose release was already recorded is completed instead. It never
// re-dispatches anything. Unknown disclosure is surfaced, not guessed away.
func (rc *Recorder) Recover(ctx context.Context, admittedBefore time.Time) (int, error) {
	rc.defaults()
	wc, cancel := rc.wctx(ctx)
	open, err := rc.Backend.OpenTurns(wc, admittedBefore)
	cancel()
	if err != nil {
		return 0, err
	}
	n := 0
	var firstErr error
	for _, o := range open {
		t := &turn{rc: rc, tenant: o.TenantID, id: o.TurnID}
		if err := rc.resolve(ctx, t, "crash_recovery"); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("recover turn %s: %w", o.TurnID, err)
			}
			continue
		}
		n++
	}
	return n, firstErr
}

// payloadKeyDenied are key names that must never appear in an event payload:
// credentials, auth headers and telemetry. The exact user input and source
// excerpts are stored as objects, not as payload keys.
var payloadKeyDenied = []string{"authorization", "token", "cookie", "secret", "password", "api_key", "apikey",
	"bearer", "header", "user_agent", "ip_address", "telemetry"}

// screen rejects payloads carrying credential-, header- or telemetry-like keys,
// at any depth. Payloads are built by the recorder, so a hit is a programming
// error that must fail the write rather than store a secret.
func screen(v any) error {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			lk := strings.ToLower(k)
			for _, bad := range payloadKeyDenied {
				if strings.Contains(lk, bad) {
					return fmt.Errorf("evidence: payload key %q is not allowed in evidence", k)
				}
			}
			if err := screen(c); err != nil {
				return err
			}
		}
	case []any:
		for _, c := range x {
			if err := screen(c); err != nil {
				return err
			}
		}
	}
	return nil
}

// Screen exposes the payload screen for tests of the credential/telemetry rule.
func Screen(v any) error { return screen(v) }
