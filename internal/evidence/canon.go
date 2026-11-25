// Package evidence implements the Charter evidence contract (ADR 0001): the
// canonical hash chain, the independent verifier, the durable write path and
// crash recovery. It is the only code that writes evidence.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const maxSafeInt = 1<<53 - 1

// Event is one JSON object of the v1 schema. It stays a generic map so unknown
// (newer MINOR) fields are preserved and hashed, as versioning.md requires.
type Event = map[string]any

// SHA256 returns "sha256:<64 lowercase hex>" over raw bytes.
func SHA256(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Canonical encodes v as the constrained RFC 8785 subset of ADR 0001 section 6:
// UTF-8, keys sorted by UTF-16 code units, no whitespace, strings, booleans,
// null, arrays, objects and integers within +/-(2^53-1). Floats, larger
// integers, invalid UTF-8 and unsupported Go types are errors.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := enc(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func enc(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		return encString(b, x)
	case int:
		return encInt(b, int64(x))
	case int32:
		return encInt(b, int64(x))
	case int64:
		return encInt(b, x)
	case uint32:
		return encInt(b, int64(x))
	case uint64:
		if x > maxSafeInt {
			return errors.New("canonical: integer outside the IEEE-754 safe range; use a decimal string")
		}
		return encInt(b, int64(x))
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil {
			return fmt.Errorf("canonical: %q is not a safe integer (floats are forbidden)", string(x))
		}
		return encInt(b, n)
	case float32, float64:
		return errors.New("canonical: floats are forbidden in events")
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := enc(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		a := make([]any, len(x))
		for i, s := range x {
			a[i] = s
		}
		return enc(b, a)
	case []map[string]any:
		a := make([]any, len(x))
		for i, m := range x {
			a[i] = m
		}
		return enc(b, a)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			if !utf8.ValidString(k) {
				return errors.New("canonical: invalid UTF-8 in key")
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := enc(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
	return nil
}

func encInt(b *bytes.Buffer, n int64) error {
	if n > maxSafeInt || n < -maxSafeInt {
		return errors.New("canonical: integer outside the IEEE-754 safe range; use a decimal string")
	}
	b.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func encString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("canonical: invalid UTF-8 / lone surrogate in string")
	}
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// ParseJSON decodes one JSON document into generic values suitable for
// Canonical. Numbers stay json.Number (so floats are detected, not rounded),
// duplicate-free structure is the caller's concern, trailing data is an error,
// and an unpaired \uD800-\uDFFF escape is rejected instead of silently becoming
// U+FFFD (which would change the hash).
func ParseJSON(raw []byte) (any, error) {
	if err := checkSurrogates(raw); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errors.New("trailing data after JSON document")
	}
	return v, nil
}

func checkSurrogates(raw []byte) error {
	s := string(raw)
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '\\' {
			continue
		}
		if s[i+1] != 'u' {
			i++ // skip any other escaped char, including an escaped backslash
			continue
		}
		if i+6 > len(s) {
			return nil // malformed; the decoder reports it
		}
		u, err := strconv.ParseUint(s[i+2:i+6], 16, 32)
		if err != nil {
			return nil
		}
		switch {
		case u >= 0xD800 && u <= 0xDBFF:
			if i+12 <= len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
				if lo, err := strconv.ParseUint(s[i+8:i+12], 16, 32); err == nil && lo >= 0xDC00 && lo <= 0xDFFF {
					i += 11
					continue
				}
			}
			return errors.New("lone surrogate escape in JSON string")
		case u >= 0xDC00 && u <= 0xDFFF:
			return errors.New("lone surrogate escape in JSON string")
		}
		i += 5
	}
	return nil
}

// EventHash is SHA-256 over the canonical JSON of the event without event_hash.
func EventHash(e Event) (string, error) {
	c := make(map[string]any, len(e))
	for k, v := range e {
		if k != "event_hash" {
			c[k] = v
		}
	}
	b, err := Canonical(c)
	if err != nil {
		return "", err
	}
	return SHA256(b), nil
}

// Seal computes and sets event_hash.
func Seal(e Event) error {
	h, err := EventHash(e)
	if err != nil {
		return err
	}
	e["event_hash"] = h
	return nil
}

// Marshal returns the canonical JSON of a sealed event (the stored body).
func Marshal(e Event) ([]byte, error) { return Canonical(e) }

// ParseEvent parses one stored event body.
func ParseEvent(raw []byte) (Event, error) {
	v, err := ParseJSON(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("event is not a JSON object")
	}
	return m, nil
}

func str(e Event, k string) string { s, _ := e[k].(string); return s }

func integer(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func payload(e Event) map[string]any {
	p, _ := e["payload"].(map[string]any)
	if p == nil {
		p = map[string]any{}
	}
	return p
}
