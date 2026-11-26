package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
)

// VerifyRetentionFull explicitly requires the retained profile. It validates
// content and receipt bindings, not live storage or an external chain anchor.
func VerifyRetentionFull(events []Event, objects map[string][]byte) []string {
	if len(events) == 0 || str(payload(events[0]), "evidence_profile") != RetentionProfile {
		return []string{"[ENVELOPE] retention evidence profile is required"}
	}
	return VerifyFull(events, objects)
}

func unmarshalRetainedReceipt(raw map[string]any) (retainedObjectReceipt, error) {
	var ret retainedObjectReceipt
	b, err := Canonical(raw)
	if err != nil {
		return ret, err
	}
	if err = json.Unmarshal(b, &ret); err != nil {
		return ret, err
	}
	if err = validateRetainedReceipt(ret); err != nil {
		return ret, err
	}
	expected, err := Canonical(mapRetainedReceipt(ret))
	if err != nil || !bytes.Equal(expected, b) {
		return ret, errors.New("unknown retained receipt fields")
	}
	return ret, nil
}

func ackRetainedReceipt(p map[string]any, target Event) (retainedObjectReceipt, bool) {
	raw, ok := asObj(p["retained_receipt"])
	if !ok {
		return retainedObjectReceipt{}, false
	}
	ret, err := unmarshalRetainedReceipt(raw)
	if err != nil {
		return retainedObjectReceipt{}, false
	}
	id, err := retainedReceiptID(ret)
	seq, validSeq := integer(target["seq"])
	hash := str(target, "event_hash")
	tenant := str(target, "tenant_id")
	key := "charter/v1/" + ret.Deployment + "/" + tenant + "/data/events/" + str(target, "turn_id") + "/" + hash
	b, bodyErr := Marshal(target)
	return ret, err == nil && bodyErr == nil && validSeq && seq > 0 && ret.Seq == uint64(seq) &&
		id == str(p, "receipt") && ret.SHA256 == SHA256(b) && ret.Length == uint64(len(b)) &&
		ret.EventHash == hash && ret.EvidenceID == hash && ret.Tenant == tenant && ret.Key == key &&
		idRe.MatchString(ret.Deployment) && idRe.MatchString(ret.Bucket)
}
