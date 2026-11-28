package evidence

import (
	"errors"
	"fmt"
)

// VerifySurvivingExportEvents verifies the verifiable material in a retained
// partial chain. A nil error is not full lifecycle verification when any
// event is missing. Custodian and admission time must be separately checked
// against the authenticated snapshot when event zero is missing.
func VerifySurvivingExportEvents(events []Event, end int64, holes []int64) error {
	if len(events) == 0 || end < 0 || end >= 100000 || int64(len(events)+len(holes)) != end+1 {
		return errors.New("invalid partial sequence census")
	}
	missing := make(map[int64]bool, len(holes))
	prevHole := int64(-1)
	for _, seq := range holes {
		if seq <= prevHole || seq > end {
			return errors.New("invalid missing sequence")
		}
		missing[seq] = true
		prevHole = seq
	}
	var errs []string
	add := func(i int, code, f string, args ...any) {
		errs = append(errs, fmt.Sprintf("seq %d: %s: %s", i, code, fmt.Sprintf(f, args...)))
	}
	var prev Event
	prevSeq := int64(-2)
	next := int64(0)
	for _, e := range events {
		for missing[next] {
			next++
		}
		seq, ok := integer(e["seq"])
		if !ok || seq != next {
			return errors.New("missing, duplicated or reordered sequence")
		}
		next++
		envelope(int(seq), e, events[0], add)
		h, err := EventHash(e)
		if err != nil || h != str(e, "event_hash") {
			return errors.New("retained event hash mismatch")
		}
		typ := str(e, "type")
		p := payload(e)
		actor := actorOf(e)
		if !knownType[typ] || (typ == "turn_received") != (seq == 0) || (isTerminal(typ) && seq != end) || (seq == end && !isTerminal(typ)) {
			return errors.New("invalid retained event type at frozen sequence")
		}
		if seq == 0 {
			if p["evidence_profile"] != RetentionProfile || e["prev_hash"] != nil || str(actor, "kind") != "user" {
				return errors.New("invalid retained admission profile or actor")
			}
			checkCurrentEvent(events, 0, typ, p, add)
		} else {
			if str(actor, "kind") != "service" || !validRetainedDigest(str(e, "prev_hash")) || (prevSeq == seq-1 && str(e, "prev_hash") != str(prev, "event_hash")) {
				return errors.New("invalid retained predecessor or actor")
			}
		}
		if typ == "evidence_ack" {
			if prevSeq == seq-1 {
				if _, ok := ackRetainedReceipt(p, prev); !ok {
					return errors.New("invalid retained receipt binding")
				}
			} else {
				raw, ok := asObj(p["retained_receipt"])
				if !ok {
					return errors.New("missing surviving receipt")
				}
				r, err := unmarshalRetainedReceipt(raw)
				if err != nil {
					return err
				}
				id, err := retainedReceiptID(r)
				acked, ok := integer(p["acked_seq"])
				ph := str(e, "prev_hash")
				tenant := str(e, "tenant_id")
				turn := str(e, "turn_id")
				if err != nil || !ok || acked != seq-1 || seq < 2 || str(p, "acked_event_hash") != ph || r.EventHash != ph || r.EvidenceID != ph || r.Seq != uint64(acked) || r.Tenant != tenant || r.Key != "charter/v1/"+r.Deployment+"/"+tenant+"/data/events/"+turn+"/"+ph || str(p, "receipt") != id || str(p, "storage_level") != "s3:object-lock:COMPLIANCE" {
					return errors.New("receipt does not bind the missing predecessor")
				}
			}
		}
		prev, prevSeq = e, seq
	}
	if len(errs) > 0 {
		return errors.New(errs[0])
	}
	if len(holes) == 0 {
		if problems := VerifyStructure(events); len(problems) > 0 {
			return errors.New(problems[0])
		}
	}
	return nil
}
