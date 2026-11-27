package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"maps"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
)

type retentionTransport interface {
	Bucket() string
	Create(context.Context, string, []byte, time.Time) (string, error)
	Read(context.Context, string, string) (s3transport.Version, error)
	Versions(context.Context, string) ([]s3transport.Ref, error)
}

// RetentionOptions binds the storage authority. A public key alone permits
// read-only reconstruction without a PostgreSQL evidence index.
type RetentionOptions struct {
	Store              retentionTransport
	Deployment, Bucket string
	TrustedCommitKey   ed25519.PublicKey
	MinimumRetention   time.Time
	Signer             ed25519.PrivateKey
	RetainFor          time.Duration
	Fence              *Fence
	Probe              func(context.Context) error
}
type RetentionBackend struct {
	store                      retentionTransport
	deployment, bucket, prefix string
	trustedKey                 ed25519.PublicKey
	minimumRetention           time.Time
	signer                     ed25519.PrivateKey
	retainFor                  time.Duration
	fence                      *Fence
	probe                      func(context.Context) error
}

func NewRetentionBackend(o RetentionOptions) (*RetentionBackend, error) {
	if o.Store == nil || !idRe.MatchString(o.Deployment) || !idRe.MatchString(o.Bucket) || len(o.TrustedCommitKey) != ed25519.PublicKeySize {
		return nil, errors.New("evidence: incomplete S3 retention options")
	}
	if o.Store.Bucket() != o.Bucket {
		return nil, errors.New("evidence: S3 bucket binding mismatch")
	}
	if len(o.Signer) != 0 && (len(o.Signer) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(o.Signer[:ed25519.SeedSize]), o.Signer) || !bytes.Equal(o.Signer.Public().(ed25519.PublicKey), o.TrustedCommitKey) || o.Fence == nil || o.RetainFor < time.Minute) {
		return nil, errors.New("evidence: unsafe retained write configuration")
	}
	return &RetentionBackend{store: o.Store, deployment: o.Deployment, bucket: o.Bucket, prefix: "charter/v1/" + o.Deployment + "/", trustedKey: bytes.Clone(o.TrustedCommitKey), minimumRetention: o.MinimumRetention.UTC(), signer: bytes.Clone(o.Signer), retainFor: o.RetainFor, fence: o.Fence, probe: o.Probe}, nil
}
func (*RetentionBackend) Info() BackendInfo {
	return BackendInfo{Kind: RetentionProfile, RetentionEnforced: false, Notice: "S3 Object Lock candidate; real-storage qualification has not been demonstrated."}
}

type retainedEntry struct {
	commit  retainedCommit
	marker  retainedMarkerReceipt
	event   Event
	objects map[string][]byte
}

func (b *RetentionBackend) retentionOK(v s3transport.Version, id string) bool {
	return id != "" && id != "null" && v.ID == id && v.Mode == "COMPLIANCE" && v.Until.After(time.Now()) && !v.Until.Before(b.minimumRetention)
}
func decodeSignedCandidate(raw []byte, key ed25519.PublicKey) (retainedCommit, error) {
	env, err := ParseJSON(raw)
	if err != nil {
		return retainedCommit{}, err
	}
	m, ok := asObj(env)
	if !ok {
		return retainedCommit{}, ErrConflict
	}
	ps, ok := m["payload"].(string)
	if !ok {
		return retainedCommit{}, ErrConflict
	}
	p, err := ParseJSON([]byte(ps))
	if err != nil {
		return retainedCommit{}, err
	}
	c, err := decodeRetainedCommit(p)
	if err != nil {
		return retainedCommit{}, err
	}
	_, err = verifyRetainedCommit(raw, key, retainedCoordinates{Deployment: c.Deployment, Tenant: c.Tenant, Project: c.Project, Turn: c.Turn, Seq: c.Seq, Slot: c.Slot})
	return c, err
}
func (b *RetentionBackend) slot(ctx context.Context, key string, refs []s3transport.Ref) (retainedEntry, error) {
	var selected *retainedEntry
	present, readable := false, false
	for _, r := range refs {
		if r.Key != key {
			continue
		}
		present = true
		if r.DeleteMarker {
			continue
		}
		v, err := b.store.Read(ctx, key, r.VersionID)
		if errors.Is(err, s3transport.ErrObjectAbsent) {
			// The version vanished between listing and read: a mid-deletion
			// key, not a namespace integrity violation.
			continue
		}
		if err != nil {
			return retainedEntry{}, err
		}
		readable = true
		c, err := decodeSignedCandidate(v.Data, b.trustedKey)
		if err != nil {
			continue
		}
		if !b.retentionOK(v, r.VersionID) {
			return retainedEntry{}, ErrNotDurable
		}
		if c.Slot != key || c.Deployment != b.deployment || !idRe.MatchString(c.Tenant) || !idRe.MatchString(c.Project) || !idRe.MatchString(c.Turn) || selected != nil {
			return retainedEntry{}, ErrConflict
		}
		selected = &retainedEntry{commit: c, marker: retainedMarkerReceipt{Bucket: b.bucket, Key: key, Version: v.ID, SHA256: SHA256(v.Data), Length: uint64(len(v.Data)), Mode: v.Mode, RetainUntil: v.Until.UTC().Format(time.RFC3339)}}
	}
	if selected == nil {
		if readable {
			// A live, readable version that did not yield a valid candidate
			// is a namespace integrity violation: fail closed.
			return retainedEntry{}, ErrConflict
		}
		if present {
			return retainedEntry{}, ErrConflict
		}
		return retainedEntry{}, ErrNotFound
	}
	return *selected, nil
}
func compatibleMarker(saved, live retainedMarkerReceipt) bool {
	// COMPLIANCE may be extended but must never be shortened.
	return saved.Bucket == live.Bucket && saved.Key == live.Key && saved.Version == live.Version && saved.SHA256 == live.SHA256 && saved.Length == live.Length && saved.Mode == live.Mode && saved.RetainUntil <= live.RetainUntil
}
func (b *RetentionBackend) retainedBytes(ctx context.Context, r retainedObjectReceipt) ([]byte, error) {
	if r.Bucket != b.bucket || r.Deployment != b.deployment {
		return nil, ErrConflict
	}
	v, err := b.store.Read(ctx, r.Key, r.Version)
	if err != nil {
		return nil, err
	}
	if !b.retentionOK(v, r.Version) || v.Until.UTC().Format(time.RFC3339) < r.RetainUntil || SHA256(v.Data) != r.SHA256 || uint64(len(v.Data)) != r.Length {
		return nil, ErrNotDurable
	}
	return v.Data, nil
}
func (b *RetentionBackend) eventKey(tenant, turn, h string) string {
	return b.prefix + tenant + "/data/events/" + turn + "/" + h
}
func (b *RetentionBackend) objectKey(tenant, h string) string {
	return b.prefix + tenant + "/data/objects/" + h
}
func (b *RetentionBackend) eventSlot(tenant, turn string, seq uint64) string {
	return b.prefix + tenant + "/events/" + turn + "/" + strconv.FormatUint(seq, 10)
}
func (b *RetentionBackend) eventData(ctx context.Context, ent *retainedEntry) error {
	c := ent.commit
	if c.Event.Key != b.eventKey(c.Tenant, c.Turn, c.EventHash) || c.Event.EvidenceID != c.EventHash || c.Event.Tenant != c.Tenant {
		return ErrConflict
	}
	raw, err := b.retainedBytes(ctx, c.Event)
	if err != nil {
		return err
	}
	e, err := ParseEvent(raw)
	if err != nil {
		return ErrConflict
	}
	canonical, err := checkedBody(e)
	seq, ok := integer(e["seq"])
	if err != nil || !bytes.Equal(raw, canonical) || !ok || seq < 0 || uint64(seq) != c.Seq || str(e, "event_hash") != c.EventHash || str(e, "tenant_id") != c.Tenant || str(e, "project_id") != c.Project || str(e, "turn_id") != c.Turn {
		return ErrConflict
	}
	if c.Seq == 0 && (str(e, "type") != "turn_received" || str(actorOf(e), "kind") != "user" || str(payload(e), "custodian_id") != str(actorOf(e), "id")) {
		return ErrConflict
	}
	ent.event = e
	want := map[string]int64{}
	for _, r := range eventRefs(e) {
		if n, ok := want[r.sha]; ok && n != r.bytes {
			return ErrConflict
		}
		want[r.sha] = r.bytes
	}
	ent.objects = map[string][]byte{}
	for _, r := range c.Objects {
		n, ok := want[r.SHA256]
		if !ok || n < 0 || uint64(n) != r.Length || r.Tenant != c.Tenant || r.EvidenceID != r.SHA256 || r.Key != b.objectKey(c.Tenant, r.SHA256) || r.EventHash != "" || r.Seq != 0 {
			return ErrConflict
		}
		data, err := b.retainedBytes(ctx, r)
		if err != nil {
			return err
		}
		ent.objects[r.SHA256] = data
	}
	if len(ent.objects) != len(want) {
		return ErrNotDurable
	}
	return nil
}

// admissionsRelaxed enumerates every admission marker of the namespace with
// signature and identity verification but WITHOUT the active-retention
// requirement: retention-expired evidence legally coexists with new captures
// (the C07 lifecycle disposes expired turns while the tenant keeps serving),
// so an unrelated expired admission must not abort a serving read or append.
// The strict durability requirement applies to the entries the caller
// actually uses (the target turn of a read, the target of an append).
func (b *RetentionBackend) admissionsRelaxed(ctx context.Context, refs []s3transport.Ref) ([]retainedEntry, error) {
	keys := map[string]bool{}
	for _, r := range refs {
		p := strings.Split(strings.TrimPrefix(r.Key, b.prefix), "/")
		if len(p) < 2 || p[1] != "admissions" {
			continue
		}
		if len(p) != 3 || !idRe.MatchString(p[0]) || !validRetainedDigest(p[2]) {
			return nil, ErrConflict
		}
		keys[r.Key] = true
	}
	var out []retainedEntry
	for key := range keys {
		e, err := b.slotRelaxed(ctx, key, refs)
		if errors.Is(err, ErrNotFound) {
			// Mid-deletion admission: the marker is already deleted; the
			// durable disposal plan governs the turn's remaining versions.
			continue
		}
		if err != nil {
			return nil, err
		}
		c := e.commit
		if c.Seq != 0 || c.Admission == nil || key != b.prefix+c.Tenant+"/admissions/"+c.Admission.IdempotencyDigest {
			return nil, ErrConflict
		}
		out = append(out, e)
	}
	return out, nil
}
func (b *RetentionBackend) turnFrom(ctx context.Context, a retainedEntry, refs []s3transport.Ref) ([]retainedEntry, error) {
	if err := b.eventData(ctx, &a); err != nil {
		return nil, err
	}
	c := a.commit
	root := b.prefix + c.Tenant + "/events/" + c.Turn + "/"
	seqs := map[uint64]bool{}
	for _, r := range refs {
		if !strings.HasPrefix(r.Key, root) {
			continue
		}
		s := strings.TrimPrefix(r.Key, root)
		seq, err := strconv.ParseUint(s, 10, 53)
		if err != nil || seq == 0 || strconv.FormatUint(seq, 10) != s {
			return nil, ErrConflict
		}
		seqs[seq] = true
	}
	result := []retainedEntry{a}
	for i := uint64(1); i <= uint64(len(seqs)); i++ {
		prev := result[len(result)-1]
		if !seqs[i] || isTerminal(str(prev.event, "type")) {
			return nil, ErrConflict
		}
		ent, err := b.slot(ctx, b.eventSlot(c.Tenant, c.Turn, i), refs)
		if err != nil {
			return nil, err
		}
		e := ent.commit
		if e.Seq != i || e.Project != c.Project || e.Turn != c.Turn || e.Tenant != c.Tenant || e.Predecessor == nil || !compatibleMarker(*e.Predecessor, prev.marker) {
			return nil, ErrConflict
		}
		if err = b.eventData(ctx, &ent); err != nil {
			return nil, err
		}
		if str(ent.event, "prev_hash") != prev.commit.EventHash || str(ent.event, "matter_id") != str(a.event, "matter_id") {
			return nil, ErrConflict
		}
		if str(ent.event, "type") == "evidence_ack" {
			r, ok := ackRetainedReceipt(payload(ent.event), prev.event)
			if !ok || r != prev.commit.Event {
				return nil, ErrConflict
			}
		}
		result = append(result, ent)
	}
	return result, nil
}
func (b *RetentionBackend) readTurn(ctx context.Context, tenant, turn string) ([]retainedEntry, error) {
	if !idRe.MatchString(tenant) || !idRe.MatchString(turn) {
		return nil, ErrNotFound
	}
	refs, err := b.store.Versions(ctx, b.prefix+tenant+"/")
	if err != nil {
		return nil, err
	}
	admissions, err := b.admissionsRelaxed(ctx, refs)
	if err != nil {
		return nil, err
	}
	var found *retainedEntry
	for i := range admissions {
		a := admissions[i]
		if a.commit.Turn != turn {
			continue
		}
		if a.commit.Tenant != tenant {
			return nil, ErrConflict
		}
		if found != nil {
			return nil, ErrConflict
		}
		// The TARGET admission must itself be durable (active COMPLIANCE
		// retention) for a serving read or append; unrelated expired
		// admissions are enumerated relaxed above.
		v, err := b.store.Read(ctx, a.commit.Slot, a.marker.Version)
		if err != nil {
			return nil, err
		}
		if !b.retentionOK(v, a.marker.Version) {
			return nil, ErrNotDurable
		}
		found = &a
	}
	if found == nil {
		return nil, ErrNotFound
	}
	return b.turnFrom(ctx, *found, refs)
}
func (b *RetentionBackend) Load(ctx context.Context, tenant, turn string) ([]Event, error) {
	entries, err := b.readTurn(ctx, tenant, turn)
	if err != nil {
		return nil, err
	}
	out := make([]Event, len(entries))
	for i, e := range entries {
		out[i] = e.event
	}
	return out, nil
}
func (b *RetentionBackend) LoadRetainedObjects(ctx context.Context, tenant, turn string, expected []Event) (map[string][]byte, error) {
	entries, err := b.readTurn(ctx, tenant, turn)
	if err != nil {
		return nil, err
	}
	if len(expected) == 0 || len(entries) != len(expected) {
		return nil, ErrConflict
	}
	out := map[string][]byte{}
	for i, e := range entries {
		body, err := checkedBody(expected[i])
		if err != nil || SHA256(body) != e.commit.Event.SHA256 {
			return nil, ErrConflict
		}
		maps.Copy(out, e.objects)
	}
	return out, nil
}
func (b *RetentionBackend) VerifyRetainedTurn(ctx context.Context, tenant, turn string, expected []Event) error {
	if b.probe != nil {
		if err := b.probe(ctx); err != nil {
			return err
		}
	}
	objs, err := b.LoadRetainedObjects(ctx, tenant, turn, expected)
	if err != nil {
		return err
	}
	if len(verifyChain(expected, objs, true, true)) != 0 {
		return ErrConflict
	}
	return nil
}
func (b *RetentionBackend) OpenTurns(ctx context.Context, before time.Time) ([]TurnRef, error) {
	refs, err := b.store.Versions(ctx, b.prefix)
	if err != nil {
		return nil, err
	}
	admissions, err := b.admissionsRelaxed(ctx, refs)
	if err != nil {
		return nil, err
	}
	seen := map[TurnRef]bool{}
	var out []TurnRef
	for _, a := range admissions {
		id := TurnRef{TenantID: a.commit.Tenant, TurnID: a.commit.Turn}
		if seen[id] {
			return nil, ErrConflict
		}
		seen[id] = true
		es, err := b.turnFrom(ctx, a, refs)
		if errors.Is(err, ErrNotDurable) {
			// A retention-expired open turn cannot be durably recovered;
			// its lifecycle disposal is the correct next step. Skipped
			// conservatively - never a silent corruption pass-through.
			continue
		}
		if err != nil {
			return nil, err
		}
		stamp, err := time.Parse(time.RFC3339Nano, str(es[0].event, "recorded_at"))
		if err != nil {
			return nil, ErrConflict
		}
		if !isTerminal(str(es[len(es)-1].event, "type")) && (before.IsZero() || stamp.Before(before)) {
			out = append(out, id)
		}
	}
	for _, r := range refs {
		p := strings.Split(strings.TrimPrefix(r.Key, b.prefix), "/")
		if len(p) >= 2 && p[1] == "events" && (len(p) != 4 || !seen[TurnRef{TenantID: p[0], TurnID: p[2]}]) {
			return nil, ErrConflict
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID == out[j].TenantID {
			return out[i].TurnID < out[j].TurnID
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out, nil
}

func (b *RetentionBackend) slotRelaxed(ctx context.Context, key string, refs []s3transport.Ref) (retainedEntry, error) {
	var selected *retainedEntry
	present, readable := false, false
	for _, r := range refs {
		if r.Key != key {
			continue
		}
		present = true
		if r.DeleteMarker {
			continue
		}
		v, err := b.store.Read(ctx, key, r.VersionID)
		if errors.Is(err, s3transport.ErrObjectAbsent) {
			// Mid-deletion key: the version is gone; only its listing (or a
			// delete marker) remains. Not an integrity violation.
			continue
		}
		if err != nil {
			return retainedEntry{}, err
		}
		readable = true
		c, err := decodeSignedCandidate(v.Data, b.trustedKey)
		if err != nil {
			continue
		}
		if v.ID != r.VersionID || v.Mode != "COMPLIANCE" || c.Slot != key || c.Deployment != b.deployment || !idRe.MatchString(c.Tenant) || !idRe.MatchString(c.Project) || !idRe.MatchString(c.Turn) || selected != nil {
			return retainedEntry{}, ErrConflict
		}
		selected = &retainedEntry{commit: c, marker: retainedMarkerReceipt{Bucket: b.bucket, Key: key, Version: v.ID, SHA256: SHA256(v.Data), Length: uint64(len(v.Data)), Mode: v.Mode, RetainUntil: v.Until.UTC().Format(time.RFC3339)}}
	}
	if selected == nil {
		if readable {
			// A live, readable version without a valid candidate fails
			// closed.
			return retainedEntry{}, ErrConflict
		}
		if present {
			// Only deleted/absent versions remain listed: the key is gone
			// (mid-deletion), so it is NOT present for enumeration.
			return retainedEntry{}, ErrNotFound
		}
		return retainedEntry{}, ErrNotFound
	}
	return *selected, nil
}

// eventZeroIdentity extracts the lifecycle identity (matter, custodian,
// recorded time) from an admission's event-0 bytes without requiring the
// whole chain or active retention.
func (b *RetentionBackend) eventZeroIdentity(ctx context.Context, ent retainedEntry) (TurnIdentity, error) {
	c := ent.commit
	if c.Seq != 0 || c.Admission == nil {
		return TurnIdentity{}, ErrConflict
	}
	v, err := b.store.Read(ctx, c.Event.Key, c.Event.Version)
	if err != nil {
		return TurnIdentity{}, err
	}
	e, err := ParseEvent(v.Data)
	if err != nil {
		return TurnIdentity{}, ErrConflict
	}
	stamp, err := time.Parse(time.RFC3339Nano, str(e, "recorded_at"))
	if err != nil {
		return TurnIdentity{}, ErrConflict
	}
	if str(e, "tenant_id") != c.Tenant || str(e, "project_id") != c.Project || str(e, "turn_id") != c.Turn || str(e, "type") != "turn_received" || str(actorOf(e), "id") == "" {
		return TurnIdentity{}, ErrConflict
	}
	return TurnIdentity{TenantID: c.Tenant, ProjectID: c.Project, MatterID: str(e, "matter_id"), CustodianID: str(actorOf(e), "id"), TurnID: c.Turn, RecordedAt: stamp}, nil
}

// InventoryTurns enumerates every admitted turn of the tenant from the
// retained namespace: an exhaustive bounded scan of admission markers, each
// verified by signature and exact event-0 bytes. Retention state is
// deliberately NOT required here: the lifecycle must see expired evidence
// (sweeping and disposing it is its purpose); serving paths keep their own
// strict durability invariant.
func (b *RetentionBackend) InventoryTurns(ctx context.Context, tenantID string) ([]TurnIdentity, error) {
	if !idRe.MatchString(tenantID) {
		return nil, ErrNotFound
	}
	refs, err := b.store.Versions(ctx, b.prefix+tenantID+"/")
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	for _, r := range refs {
		p := strings.Split(strings.TrimPrefix(r.Key, b.prefix), "/")
		if len(p) < 2 || p[1] != "admissions" {
			continue
		}
		if len(p) != 3 || !idRe.MatchString(p[0]) || !validRetainedDigest(p[2]) {
			return nil, ErrConflict
		}
		keys[r.Key] = true
	}
	out := make([]TurnIdentity, 0, len(keys))
	for key := range keys {
		ent, err := b.slotRelaxed(ctx, key, refs)
		if errors.Is(err, ErrNotFound) {
			// The admission marker is deleted (mid-deletion turn): the turn
			// is no longer enumerable from live inventory.
			continue
		}
		if err != nil {
			return nil, err
		}
		id, err := b.eventZeroIdentity(ctx, ent)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TurnID < out[j].TurnID })
	return out, nil
}

// TurnDisposalRefs enumerates the exact versions that make up one turn for
// DISPOSAL: the admission marker, every event slot, every data event and
// every content-addressed object the signed commits reference. Retention
// state is deliberately NOT required (expired evidence is exactly what
// disposal operates on); signatures and exact version identity are still
// verified. The deleter itself is refused by the storage while any version
// remains protected, so an unexpired version can never slip through.
func (b *RetentionBackend) TurnDisposalRefs(ctx context.Context, tenantID, turnID string) ([]VersionRef, error) {
	if !idRe.MatchString(tenantID) || !idRe.MatchString(turnID) {
		return nil, ErrNotFound
	}
	refs, err := b.store.Versions(ctx, b.prefix+tenantID+"/")
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	for _, r := range refs {
		p := strings.Split(strings.TrimPrefix(r.Key, b.prefix), "/")
		if len(p) < 2 || p[1] != "admissions" {
			continue
		}
		keys[r.Key] = true
	}
	var admission *retainedEntry
	for key := range keys {
		ent, err := b.slotRelaxed(ctx, key, refs)
		if errors.Is(err, ErrNotFound) {
			// Another turn's admission is mid-deletion; it cannot acquire
			// new references and its own disposal plan governs it.
			continue
		}
		if err != nil {
			return nil, err
		}
		if ent.commit.Turn == turnID {
			if admission != nil || ent.commit.Tenant != tenantID {
				return nil, ErrConflict
			}
			e := ent
			admission = &e
		}
	}
	if admission == nil {
		return nil, ErrNotFound
	}
	seen := map[VersionRef]bool{}
	add := func(key, version string) {
		if key == "" || version == "" {
			return
		}
		seen[VersionRef{Key: key, Version: version}] = true
	}
	// Walk every event slot of the turn, verifying each signed commit's
	// predecessor binding exactly like the serving read, minus the
	// retention-duration requirement.
	root := b.prefix + tenantID + "/events/" + turnID + "/"
	seqs := map[uint64]string{}
	for _, r := range refs {
		if !strings.HasPrefix(r.Key, root) {
			continue
		}
		s := strings.TrimPrefix(r.Key, root)
		seq, err := strconv.ParseUint(s, 10, 53)
		if err != nil || strconv.FormatUint(seq, 10) != s {
			return nil, ErrConflict
		}
		if seq == 0 {
			// Sequence 0 lives only as the admission marker; the events
			// namespace starts at 1.
			return nil, ErrConflict
		}
		if prev, ok := seqs[seq]; ok && prev != r.VersionID {
			return nil, ErrConflict
		}
		seqs[seq] = r.VersionID
	}
	// Chain contiguity: an event-slot set with a hole (a deleted or missing
	// middle slot while higher slots remain) means the turn's exact version
	// set is UNVERIFIABLE - silently truncating the walk would acknowledge
	// partial coverage as complete (C07 review finding 2). Fail closed.
	if len(seqs) > 0 {
		maxSeq := uint64(0)
		for seq := range seqs {
			if seq > maxSeq {
				maxSeq = seq
			}
		}
		for i := uint64(1); i <= maxSeq; i++ {
			if _, ok := seqs[i]; !ok {
				return nil, ErrConflict
			}
		}
	}
	var prevMarker *retainedMarkerReceipt
	for i := uint64(0); ; i++ {
		var key, version string
		if i == 0 {
			key, version = admission.commit.Slot, admission.marker.Version
		} else {
			v, ok := seqs[i]
			if !ok {
				break
			}
			key, version = b.eventSlot(tenantID, turnID, i), v
		}
		v, err := b.store.Read(ctx, key, version)
		if err != nil {
			return nil, err
		}
		c, err := decodeSignedCandidate(v.Data, b.trustedKey)
		if err != nil || c.Slot != key || c.Turn != turnID || c.Tenant != tenantID || c.Seq != i || v.ID != version || v.Mode != "COMPLIANCE" {
			return nil, ErrConflict
		}
		if i > 0 && (c.Predecessor == nil || prevMarker == nil || !compatibleMarker(*c.Predecessor, *prevMarker)) {
			return nil, ErrConflict
		}
		add(key, version)
		add(c.Event.Key, c.Event.Version)
		for _, o := range c.Objects {
			add(o.Key, o.Version)
		}
		m := retainedMarkerReceipt{Bucket: b.bucket, Key: key, Version: v.ID, SHA256: SHA256(v.Data), Length: uint64(len(v.Data)), Mode: v.Mode, RetainUntil: v.Until.UTC().Format(time.RFC3339)}
		prevMarker = &m
	}
	out := make([]VersionRef, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// TurnNamespaceRefs enumerates every version under the turn's own namespaces
// (event slots and data events) plus the object versions referenced by the
// still-decodable slots, WITHOUT chain verification. See the interface
// comment in inventory.go: this is the shared-reference scan's fallback for
// a sibling whose verified enumeration is unavailable.
//
// The result is classified for completeness (C07 round-2 finding 3): a
// listed slot whose read fails (other than mid-deletion absence), whose
// signed candidate cannot be verified, whose key holds only delete
// markers, or a hole in the listed slot sequence, all mean the turn's true
// reference set is a strict superset of the returned one (unknown object
// references). An unreadable reference is never treated as an absent one.
func (b *RetentionBackend) TurnNamespaceRefs(ctx context.Context, tenantID, turnID string) (NamespaceEnumeration, error) {
	if !idRe.MatchString(tenantID) || !idRe.MatchString(turnID) {
		return NamespaceEnumeration{}, ErrNotFound
	}
	refs, err := b.store.Versions(ctx, b.prefix+tenantID+"/")
	if err != nil {
		return NamespaceEnumeration{}, err
	}
	out := map[VersionRef]bool{}
	add := func(key, version string) {
		if key == "" || version == "" {
			return
		}
		out[VersionRef{Key: key, Version: version}] = true
	}
	complete := true
	slotRoot := b.prefix + tenantID + "/events/" + turnID + "/"
	dataRoot := b.prefix + tenantID + "/data/events/" + turnID + "/"
	seqs := map[uint64]bool{}
	decoded := map[uint64]bool{}
	for _, r := range refs {
		switch {
		case strings.HasPrefix(r.Key, slotRoot):
			s := strings.TrimPrefix(r.Key, slotRoot)
			seq, serr := strconv.ParseUint(s, 10, 53)
			if serr != nil || strconv.FormatUint(seq, 10) != s {
				return NamespaceEnumeration{}, ErrConflict
			}
			seqs[seq] = true
			if r.DeleteMarker {
				// Only delete markers remain listed under this slot key:
				// the slot's data version is gone, so its object
				// references are unknown - never silently absent.
				complete = false
				continue
			}
			add(r.Key, r.VersionID)
			v, err := b.store.Read(ctx, r.Key, r.VersionID)
			if err != nil {
				if errors.Is(err, s3transport.ErrObjectAbsent) {
					// Listed but gone (mid-deletion): this slot's object
					// references are unknowable.
					complete = false
					continue
				}
				return NamespaceEnumeration{}, err
			}
			c, err := decodeSignedCandidate(v.Data, b.trustedKey)
			if err != nil || c.Turn != turnID || c.Tenant != tenantID {
				// A live, readable slot whose candidate cannot be verified
				// (invalid signed metadata): its object references are
				// unknown - never silently absent.
				complete = false
				continue
			}
			decoded[seq] = true
			add(c.Event.Key, c.Event.Version)
			for _, o := range c.Objects {
				add(o.Key, o.Version)
			}
		case strings.HasPrefix(r.Key, dataRoot):
			if !r.DeleteMarker {
				add(r.Key, r.VersionID)
			}
		}
	}
	if len(seqs) > 0 {
		// A hole in the listed slot sequence: the missing slots' object
		// references are unknown.
		maxSeq := uint64(0)
		for seq := range seqs {
			if seq > maxSeq {
				maxSeq = seq
			}
		}
		for i := uint64(1); i <= maxSeq; i++ {
			if !seqs[i] || !decoded[i] {
				complete = false
			}
		}
	}
	if len(out) == 0 {
		return NamespaceEnumeration{}, ErrNotFound
	}
	res := make([]VersionRef, 0, len(out))
	for r := range out {
		res = append(res, r)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Key < res[j].Key })
	return NamespaceEnumeration{Refs: res, Complete: complete}, nil
}

// TurnVersionRefs enumerates the exact versions that make up one turn with
// the STRICT serving invariant (active COMPLIANCE retention required): used
// by hold protection, where every protected version must be verifiably
// durable. Disposal uses TurnDisposalRefs instead.
func (b *RetentionBackend) TurnVersionRefs(ctx context.Context, tenantID, turnID string) ([]VersionRef, error) {
	entries, err := b.readTurn(ctx, tenantID, turnID)
	if err != nil {
		return nil, err
	}
	seen := map[VersionRef]bool{}
	add := func(key, version string) {
		if key == "" || version == "" {
			return
		}
		seen[VersionRef{Key: key, Version: version}] = true
	}
	for _, e := range entries {
		c := e.commit
		add(c.Slot, e.marker.Version)
		add(c.Event.Key, c.Event.Version)
		for _, o := range c.Objects {
			add(o.Key, o.Version)
		}
	}
	out := make([]VersionRef, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// TurnTerminal reports whether the turn's capture reached a terminal event
// (turn_completed / turn_interrupted) by reading the highest-sequence event
// slot and its data event. Disposal eligibility requires this: an admitted,
// actively executing turn must never be destroyed by ordinary expiry (C07
// review finding 6A). Retention state is deliberately not required.
func (b *RetentionBackend) TurnTerminal(ctx context.Context, tenantID, turnID string) (bool, error) {
	if !idRe.MatchString(tenantID) || !idRe.MatchString(turnID) {
		return false, ErrNotFound
	}
	root := b.prefix + tenantID + "/events/" + turnID + "/"
	refs, err := b.store.Versions(ctx, root)
	if err != nil {
		return false, err
	}
	highest := uint64(0)
	highestVersion := ""
	for _, r := range refs {
		s := strings.TrimPrefix(r.Key, root)
		seq, err := strconv.ParseUint(s, 10, 53)
		if err != nil || strconv.FormatUint(seq, 10) != s || seq == 0 {
			return false, ErrConflict
		}
		if seq > highest {
			highest = seq
			highestVersion = r.VersionID
		}
	}
	if highest == 0 {
		// No event slots: the turn was never admitted (or is fully gone).
		return false, ErrNotFound
	}
	key := b.eventSlot(tenantID, turnID, highest)
	v, err := b.store.Read(ctx, key, highestVersion)
	if err != nil {
		return false, err
	}
	c, err := decodeSignedCandidate(v.Data, b.trustedKey)
	if err != nil || c.Slot != key || c.Turn != turnID || c.Tenant != tenantID || c.Seq != highest {
		return false, ErrConflict
	}
	ev, err := b.store.Read(ctx, c.Event.Key, c.Event.Version)
	if err != nil {
		return false, err
	}
	e, err := ParseEvent(ev.Data)
	if err != nil {
		return false, ErrConflict
	}
	if str(e, "turn_id") != turnID || str(e, "tenant_id") != tenantID {
		return false, ErrConflict
	}
	return isTerminal(str(e, "type")), nil
}
