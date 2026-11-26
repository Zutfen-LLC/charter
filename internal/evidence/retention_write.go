package evidence

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
)

var _ Backend = (*RetentionBackend)(nil)

// lockedWrite holds the existing paired ownership fence while the remote
// operation runs. Its PG transaction is a coordination/durability preflight,
// not evidence authority. A failed commit or lost fence withholds success.
func (b *RetentionBackend) lockedWrite(ctx context.Context, work func() error) error {
	if b.fence == nil || len(b.signer) == 0 {
		return ErrNotDurable
	}
	pg := PG{fence: b.fence}
	if err := func() error {
		tx, _, release, err := pg.begin(ctx)
		if err != nil {
			return err
		}
		defer release()
		defer func() {
			// The evidence deadline may have been consumed by S3. Rollback must
			// still reach PostgreSQL; pgx otherwise closes the owning session on
			// a cancelled rollback and falsely converts a storage outage to fence loss.
			clean, cancel := context.WithTimeout(context.Background(), fenceTimeout)
			defer cancel()
			_ = tx.Rollback(clean)
		}()
		if b.probe != nil {
			if err = b.probe(ctx); err != nil {
				return err
			}
		}
		if err = work(); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}(); err != nil {
		return err
	}
	return b.fence.Check(ctx)
}
func (b *RetentionBackend) writeUntil() time.Time {
	t := time.Now().UTC().Add(b.retainFor).Truncate(time.Second)
	if t.Before(b.minimumRetention) {
		return b.minimumRetention.UTC().Truncate(time.Second).Add(time.Second)
	}
	return t
}
func canReconcile(err error) bool {
	var amb *s3transport.AmbiguousError
	var remote *s3transport.Error
	return errors.As(err, &amb) || errors.Is(err, ErrConflict) || (errors.As(err, &remote) && remote.Kind == "conflict")
}

// candidate finds the unique protected byte-identical upload. An unrelated
// version at a content-derived key can never become evidence by hash alone.
func (b *RetentionBackend) candidate(ctx context.Context, key, digest string, until time.Time) (s3transport.Version, error) {
	refs, err := b.store.Versions(ctx, key)
	if err != nil {
		return s3transport.Version{}, err
	}
	var found s3transport.Version
	occupied := false
	for _, r := range refs {
		if r.Key != key {
			continue
		}
		occupied = true
		if r.DeleteMarker {
			continue
		}
		v, err := b.store.Read(ctx, key, r.VersionID)
		if err != nil {
			return s3transport.Version{}, err
		}
		if SHA256(v.Data) != digest {
			continue
		}
		if !b.retentionOK(v, r.VersionID) || v.Until.Before(until) {
			return s3transport.Version{}, ErrNotDurable
		}
		if found.ID != "" {
			return s3transport.Version{}, ErrConflict
		}
		found = v
	}
	if found.ID == "" {
		if occupied {
			return found, ErrConflict
		}
		return found, ErrNotFound
	}
	return found, nil
}
func (b *RetentionBackend) stage(ctx context.Context, key string, data []byte, until time.Time) (s3transport.Version, error) {
	digest := SHA256(data)
	v, err := b.candidate(ctx, key, digest, time.Time{})
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return v, err
	}
	id, err := b.store.Create(ctx, key, data, until)
	if err != nil {
		if !canReconcile(err) {
			return v, err
		}
		return b.candidate(ctx, key, digest, until)
	}
	v, err = b.store.Read(ctx, key, id)
	if err != nil {
		return v, err
	}
	if !b.retentionOK(v, id) || v.Until.Before(until) || !bytes.Equal(v.Data, data) {
		return s3transport.Version{}, ErrNotDurable
	}
	return v, nil
}
func (b *RetentionBackend) receiptFor(tenant, key, logicalID, hash string, seq uint64, v s3transport.Version) retainedObjectReceipt {
	return retainedObjectReceipt{Deployment: b.deployment, Tenant: tenant, EvidenceID: logicalID, Bucket: b.bucket, Key: key, Version: v.ID, SHA256: SHA256(v.Data), Length: uint64(len(v.Data)), Mode: v.Mode, RetainUntil: v.Until.UTC().Format(time.RFC3339), Seq: seq, EventHash: hash}
}
func (b *RetentionBackend) receiptFrom(r retainedObjectReceipt) (Receipt, error) {
	id, err := retainedReceiptID(r)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{Backend: RetentionProfile, Level: retentionDurableLevel, ID: id, Retained: &r}, nil
}
func (b *RetentionBackend) PutObject(ctx context.Context, tenant string, data []byte) (Receipt, error) {
	if !idRe.MatchString(tenant) {
		return Receipt{}, ErrNotFound
	}
	var rc Receipt
	err := b.lockedWrite(ctx, func() error {
		digest := SHA256(data)
		key := b.objectKey(tenant, digest)
		v, e := b.stage(ctx, key, data, b.writeUntil())
		if e != nil {
			return e
		}
		rc, e = b.receiptFrom(b.receiptFor(tenant, key, digest, "", 0, v))
		return e
	})
	if err != nil {
		return Receipt{}, err
	}
	return rc, nil
}

// Object provides the narrow Backend content lookup. R1/R2 and replay never
// use it for authority: they walk the specific turn's signed version refs.
func (b *RetentionBackend) Object(ctx context.Context, tenant, digest string) ([]byte, error) {
	if !idRe.MatchString(tenant) || !validRetainedDigest(digest) {
		return nil, ErrNotFound
	}
	v, err := b.candidate(ctx, b.objectKey(tenant, digest), digest, time.Time{})
	if err != nil {
		return nil, err
	}
	return v.Data, nil
}
func admissionDigest(a Admission) (string, error) {
	raw, err := Canonical(map[string]any{"tenant": a.TenantID, "project": a.ProjectID, "custodian": a.CustodianID, "key": a.IdempotencyKey})
	if err != nil {
		return "", err
	}
	return SHA256(append([]byte("CHARTER-RETAINED-ADMISSION-v1\x00"), raw...)), nil
}
func (b *RetentionBackend) exactSlot(ctx context.Context, key string) (retainedEntry, error) {
	refs, err := b.store.Versions(ctx, key)
	if err != nil {
		return retainedEntry{}, err
	}
	return b.slot(ctx, key, refs)
}
func (b *RetentionBackend) referenced(ctx context.Context, e Event) ([]retainedObjectReceipt, map[string][]byte, error) {
	tenant := str(e, "tenant_id")
	var receipts []retainedObjectReceipt
	objects := map[string][]byte{}
	for _, r := range eventRefs(e) {
		if data, ok := objects[r.sha]; ok {
			if int64(len(data)) != r.bytes {
				return nil, nil, ErrConflict
			}
			continue
		}
		key := b.objectKey(tenant, r.sha)
		v, err := b.candidate(ctx, key, r.sha, time.Time{})
		if err != nil {
			return nil, nil, err
		}
		if int64(len(v.Data)) != r.bytes {
			return nil, nil, ErrConflict
		}
		receipts = append(receipts, b.receiptFor(tenant, key, r.sha, "", 0, v))
		objects[r.sha] = v.Data
	}
	return sortedRetainedObjects(receipts), objects, nil
}
func (b *RetentionBackend) publish(ctx context.Context, c retainedCommit, e Event) (retainedEntry, bool, error) {
	data, err := checkedBody(e)
	if err != nil {
		return retainedEntry{}, false, err
	}
	until := b.writeUntil()
	key := b.eventKey(c.Tenant, c.Turn, c.EventHash)
	v, err := b.stage(ctx, key, data, until)
	if err != nil {
		return retainedEntry{}, false, err
	}
	c.Event = b.receiptFor(c.Tenant, key, c.EventHash, c.EventHash, c.Seq, v)
	raw, err := signRetainedCommit(c, b.signer)
	if err != nil {
		return retainedEntry{}, false, err
	}
	version, err := b.store.Create(ctx, c.Slot, raw, until)
	if err != nil && !canReconcile(err) {
		return retainedEntry{}, false, err
	}
	ent, resolveErr := b.exactSlot(ctx, c.Slot)
	if resolveErr != nil {
		return retEntErr(resolveErr)
	}
	if loadErr := b.eventData(ctx, &ent); loadErr != nil {
		return retEntErr(loadErr)
	}
	exactWinner := err == nil && ent.marker.Version == version && ent.marker.SHA256 == SHA256(raw)
	if err == nil && (!exactWinner || ent.marker.RetainUntil < until.Format(time.RFC3339)) {
		return retEntErr(ErrConflict)
	}
	if ent.marker.SHA256 == SHA256(raw) && ent.marker.RetainUntil < until.Format(time.RFC3339) {
		return retEntErr(ErrNotDurable)
	}
	return ent, exactWinner, nil
}
func retEntErr(err error) (retainedEntry, bool, error) { return retainedEntry{}, false, err }
func (b *RetentionBackend) Admit(ctx context.Context, a Admission, e Event, objects [][]byte) (AdmitResult, error) {
	var out AdmitResult
	seq, ok := integer(e["seq"])
	if !ok || seq != 0 || e["prev_hash"] != nil || str(e, "type") != "turn_received" || str(e, "tenant_id") != a.TenantID || str(e, "project_id") != a.ProjectID || str(e, "turn_id") != a.TurnID || str(e, "matter_id") != a.MatterID || str(actorOf(e), "id") != a.CustodianID || str(payload(e), "request_fingerprint") != a.Fingerprint || str(payload(e), "evidence_profile") != RetentionProfile || a.IdempotencyKey == "" || !validRetainedDigest(a.Fingerprint) {
		return out, ErrConflict
	}
	for _, s := range []string{a.TenantID, a.ProjectID, a.TurnID, a.MatterID, a.CustodianID} {
		if !idRe.MatchString(s) {
			return out, ErrConflict
		}
	}
	digest, err := admissionDigest(a)
	if err != nil {
		return out, err
	}
	slot := b.prefix + a.TenantID + "/admissions/" + digest
	err = b.lockedWrite(ctx, func() error {
		bind := func(ent retainedEntry, created bool) error {
			c := ent.commit
			if c.Admission == nil || c.Admission.IdempotencyDigest != digest || c.Tenant != a.TenantID || c.Project != a.ProjectID || str(actorOf(ent.event), "id") != a.CustodianID || str(payload(ent.event), "request_fingerprint") != c.Admission.Fingerprint || str(payload(ent.event), "evidence_profile") != RetentionProfile {
				return ErrConflict
			}
			if c.Admission.Fingerprint != a.Fingerprint {
				return ErrIdempotencyMismatch
			}
			if str(ent.event, "matter_id") != a.MatterID {
				return ErrConflict
			}
			r, err := b.receiptFrom(c.Event)
			if err != nil {
				return err
			}
			out = AdmitResult{TurnID: c.Turn, Created: created, Receipt: r}
			return nil
		}
		if ent, e2 := b.exactSlot(ctx, slot); e2 == nil {
			if e2 = b.eventData(ctx, &ent); e2 != nil {
				return e2
			}
			return bind(ent, false)
		} else if !errors.Is(e2, ErrNotFound) {
			return e2
		}
		if _, e2 := checkedBody(e); e2 != nil {
			return e2
		}
		// Admission is distinct from PUT staging; a retained staging object is not a turn.
		for _, data := range objects {
			if _, e2 := b.stage(ctx, b.objectKey(a.TenantID, SHA256(data)), data, b.writeUntil()); e2 != nil {
				return e2
			}
		}
		receipts, all, err := b.referenced(ctx, e)
		if err != nil {
			return err
		}
		if len(verifyChain([]Event{e}, all, true, true)) != 0 {
			return ErrConflict
		}
		c := retainedCommit{Schema: "charter.retained-commit.v1", Deployment: b.deployment, Slot: slot, Tenant: a.TenantID, Project: a.ProjectID, Turn: a.TurnID, EventHash: str(e, "event_hash"), Admission: &retainedAdmission{IdempotencyDigest: digest, Fingerprint: a.Fingerprint}, Objects: receipts}
		ent, created, e2 := b.publish(ctx, c, e)
		if e2 != nil {
			return e2
		}
		return bind(ent, created)
	})
	if err != nil {
		return AdmitResult{}, err
	}
	return out, nil
}
func (b *RetentionBackend) Append(ctx context.Context, e Event) (Receipt, error) {
	var result Receipt
	seq, ok := integer(e["seq"])
	if !ok || seq < 1 {
		return result, ErrConflict
	}
	body, err := checkedBody(e)
	if err != nil {
		return result, err
	}
	tenant, turn := str(e, "tenant_id"), str(e, "turn_id")
	err = b.lockedWrite(ctx, func() error {
		entries, err := b.readTurn(ctx, tenant, turn)
		if err != nil {
			return err
		}
		n := int64(len(entries))
		if seq < n {
			c := entries[seq].commit
			if c.Slot != b.eventSlot(tenant, turn, uint64(seq)) || c.Seq != uint64(seq) ||
				c.Tenant != tenant || c.Turn != turn || c.Project != str(e, "project_id") ||
				c.Predecessor == nil || !compatibleMarker(*c.Predecessor, entries[seq-1].marker) ||
				c.Event.SHA256 != SHA256(body) {
				return ErrConflict
			}
			result, err = b.receiptFrom(c.Event)
			return err
		}
		prev := entries[n-1]
		if isTerminal(str(prev.event, "type")) {
			return ErrTerminal
		}
		if seq != n || str(e, "prev_hash") != prev.commit.EventHash || str(e, "project_id") != prev.commit.Project || str(e, "matter_id") != str(prev.event, "matter_id") || str(payload(entries[0].event), "evidence_profile") != RetentionProfile {
			return ErrConflict
		}
		if str(e, "type") == "evidence_ack" {
			r, ok := ackRetainedReceipt(payload(e), prev.event)
			if !ok || r != prev.commit.Event {
				return ErrConflict
			}
		}
		receipts, objs, err := b.referenced(ctx, e)
		if err != nil {
			return err
		}
		events := make([]Event, 0, n+1)
		for _, entry := range entries {
			events = append(events, entry.event)
			maps.Copy(objs, entry.objects)
		}
		events = append(events, e)
		if len(verifyChain(events, objs, true, true)) != 0 {
			return ErrConflict
		}
		c := retainedCommit{Schema: "charter.retained-commit.v1", Deployment: b.deployment, Slot: b.eventSlot(tenant, turn, uint64(seq)), Tenant: tenant, Project: prev.commit.Project, Turn: turn, Seq: uint64(seq), EventHash: str(e, "event_hash"), Predecessor: &prev.marker, Objects: receipts}
		ent, _, e2 := b.publish(ctx, c, e)
		if e2 != nil {
			return e2
		}
		if ent.commit.Event.SHA256 != SHA256(body) || ent.commit.Predecessor == nil || !compatibleMarker(*ent.commit.Predecessor, prev.marker) {
			return ErrConflict
		}
		result, e2 = b.receiptFrom(ent.commit.Event)
		return e2
	})
	if err != nil {
		return Receipt{}, err
	}
	return result, nil
}
