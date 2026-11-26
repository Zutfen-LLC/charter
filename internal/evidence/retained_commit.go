package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

const retainedCommitDomain = "CHARTER-RETAINED-COMMIT-v1\x00"

type retainedAdmission struct {
	IdempotencyDigest string `json:"idempotency_digest"`
	Fingerprint       string `json:"fingerprint"`
}
type retainedMarkerReceipt struct {
	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	Length      uint64 `json:"length"`
	Mode        string `json:"mode"`
	RetainUntil string `json:"retain_until"`
}
type retainedObjectReceipt struct {
	Deployment  string `json:"deployment"`
	Tenant      string `json:"tenant"`
	EvidenceID  string `json:"evidence_id"`
	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	Length      uint64 `json:"length"`
	Mode        string `json:"mode"`
	RetainUntil string `json:"retain_until"`
	Seq         uint64 `json:"seq,omitempty"`
	EventHash   string `json:"event_hash,omitempty"`
}
type retainedCommit struct {
	Schema      string                  `json:"schema"`
	Deployment  string                  `json:"deployment"`
	Slot        string                  `json:"slot"`
	Tenant      string                  `json:"tenant"`
	Project     string                  `json:"project"`
	Turn        string                  `json:"turn"`
	Seq         uint64                  `json:"seq"`
	EventHash   string                  `json:"event_hash"`
	Admission   *retainedAdmission      `json:"admission,omitempty"`
	Predecessor *retainedMarkerReceipt  `json:"predecessor,omitempty"`
	Event       retainedObjectReceipt   `json:"event"`
	Objects     []retainedObjectReceipt `json:"objects"`
}
type retainedCoordinates struct {
	Deployment, Tenant, Project, Turn string
	Seq                               uint64
	Slot                              string
}

var retainedDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func signRetainedCommit(c retainedCommit, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signing key")
	}
	if err := validateRetainedCommit(c); err != nil {
		return nil, err
	}
	payload, err := Canonical(mapRetainedCommit(c))
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, append([]byte(retainedCommitDomain), payload...))
	return Canonical(map[string]any{"payload": string(payload), "signature": hex.EncodeToString(sig)})
}

func verifyRetainedCommit(raw []byte, key ed25519.PublicKey, want retainedCoordinates) ([]byte, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid verification key")
	}
	env, err := ParseJSON(raw)
	if err != nil {
		return nil, err
	}
	em, ok := env.(map[string]any)
	if !ok || len(em) != 2 {
		return nil, errors.New("invalid signed envelope")
	}
	ps, pok := em["payload"].(string)
	ss, sok := em["signature"].(string)
	if !pok || !sok {
		return nil, errors.New("invalid signed envelope")
	}
	payload := []byte(ps)
	canonicalEnvelope, err := Canonical(env)
	if err != nil || string(canonicalEnvelope) != string(raw) {
		return nil, errors.New("non-canonical envelope")
	}
	sig, err := hex.DecodeString(ss)
	if err != nil || len(sig) != ed25519.SignatureSize || hex.EncodeToString(sig) != ss || !ed25519.Verify(key, append([]byte(retainedCommitDomain), payload...), sig) {
		return nil, errors.New("invalid commit signature")
	}
	decoded, err := ParseJSON(payload)
	if err != nil {
		return nil, err
	}
	canonical, err := Canonical(decoded)
	if err != nil || string(canonical) != ps {
		return nil, errors.New("non-canonical commit payload")
	}
	c, err := decodeRetainedCommit(decoded)
	if err != nil {
		return nil, err
	}
	if err = validateRetainedCommit(c); err != nil {
		return nil, err
	}
	encoded, err := Canonical(mapRetainedCommit(c))
	if err != nil || !bytes.Equal(encoded, payload) {
		return nil, errors.New("unknown or non-canonical commit fields")
	}
	if c.Deployment != want.Deployment || c.Tenant != want.Tenant || c.Project != want.Project || c.Turn != want.Turn || c.Seq != want.Seq || c.Slot != want.Slot {
		return nil, errors.New("commit coordinate mismatch")
	}
	return payload, nil
}
func mapRetainedCommit(c retainedCommit) map[string]any {
	b, _ := json.Marshal(c)
	v, _ := ParseJSON(b)
	return v.(map[string]any)
}
func decodeRetainedCommit(v any) (retainedCommit, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return retainedCommit{}, e
	}
	var c retainedCommit
	e = json.Unmarshal(b, &c)
	return c, e
}
func validRetainedDigest(s string) bool { return retainedDigestPattern.MatchString(s) }
func validateRetainedCommit(c retainedCommit) error {
	if c.Schema != "charter.retained-commit.v1" || c.Deployment == "" || c.Tenant == "" || c.Project == "" || c.Turn == "" || c.Slot == "" || !validRetainedDigest(c.EventHash) {
		return errors.New("invalid commit coordinates or digest")
	}
	if c.Seq == 0 {
		if c.Admission == nil || c.Predecessor != nil || !validRetainedDigest(c.Admission.IdempotencyDigest) || !validRetainedDigest(c.Admission.Fingerprint) {
			return errors.New("invalid admission commitment")
		}
	} else if c.Admission != nil || c.Predecessor == nil {
		return errors.New("invalid predecessor commitment")
	}
	if err := validateRetainedReceipt(c.Event); err != nil {
		return fmt.Errorf("event receipt: %w", err)
	}
	if c.Event.Deployment != c.Deployment || c.Event.Tenant != c.Tenant || c.Event.Seq != c.Seq || c.Event.EventHash != c.EventHash {
		return errors.New("event receipt binding mismatch")
	}
	for i, r := range c.Objects {
		if err := validateRetainedReceipt(r); err != nil {
			return err
		}
		if r.Deployment != c.Deployment || r.Tenant != c.Tenant {
			return errors.New("object scope mismatch")
		}
		if i > 0 && c.Objects[i-1].EvidenceID >= r.EvidenceID {
			return errors.New("object receipts not sorted and unique")
		}
	}
	if c.Predecessor != nil {
		if err := validateMarker(*c.Predecessor); err != nil {
			return err
		}
	}
	return nil
}
func validateRetainedReceipt(r retainedObjectReceipt) error {
	if r.Deployment == "" || r.Tenant == "" || r.EvidenceID == "" || r.Bucket == "" || r.Key == "" || r.Version == "" || r.Version == "null" || !validRetainedDigest(r.SHA256) || r.Mode != "COMPLIANCE" || r.Length >= 1<<53 || r.Seq >= 1<<53 {
		return errors.New("invalid retained receipt")
	}
	t, e := time.Parse(time.RFC3339, r.RetainUntil)
	if e != nil || t.UTC().Format(time.RFC3339) != r.RetainUntil {
		return errors.New("invalid retention timestamp")
	}
	return nil
}
func validateMarker(r retainedMarkerReceipt) error {
	if r.Bucket == "" || r.Key == "" || r.Version == "" || r.Version == "null" || !validRetainedDigest(r.SHA256) || r.Mode != "COMPLIANCE" || r.Length >= 1<<53 {
		return errors.New("invalid predecessor receipt")
	}
	if t, err := time.Parse(time.RFC3339, r.RetainUntil); err != nil || t.UTC().Format(time.RFC3339) != r.RetainUntil {
		return errors.New("invalid predecessor retention timestamp")
	}
	return nil
}
func retainedReceiptID(r retainedObjectReceipt) (string, error) {
	if e := validateRetainedReceipt(r); e != nil {
		return "", e
	}
	b, e := Canonical(mapRetainedReceipt(r))
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(append([]byte("CHARTER-RETAINED-RECEIPT-v1\x00"), b...))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
func mapRetainedReceipt(r retainedObjectReceipt) map[string]any {
	b, _ := json.Marshal(r)
	v, _ := ParseJSON(b)
	m, _ := v.(map[string]any)
	return m
}
func sortedRetainedObjects(in []retainedObjectReceipt) []retainedObjectReceipt {
	out := append([]retainedObjectReceipt(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].EvidenceID < out[j].EvidenceID })
	return out
}
