package evidence

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "contracts", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The Go implementation must reproduce the cross-language golden vectors byte
// for byte (ADR 0001 section 6), including the UTF-16 key-order vector.
func TestCanonicalGoldenVectors(t *testing.T) {
	var f struct {
		Vectors []struct {
			Name   string          `json:"name"`
			Value  json.RawMessage `json:"value"`
			Hex    string          `json:"canonical_utf8_hex"`
			SHA256 string          `json:"sha256"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(fixture(t, "canonical-vectors.json"), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) < 3 {
		t.Fatal("expected the golden vectors")
	}
	for _, v := range f.Vectors {
		val, err := ParseJSON(v.Value)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		c, err := Canonical(val)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if hex.EncodeToString(c) != v.Hex || SHA256(c) != v.SHA256 {
			t.Errorf("%s: got %x %s", v.Name, c, SHA256(c))
		}
	}
}

func TestCanonicalRejectsNonPortableInput(t *testing.T) {
	for name, v := range map[string]any{
		"float64":       1.5,
		"big int":       int64(1) << 53,
		"big uint":      uint64(1) << 60,
		"invalid utf8":  "bad\xff",
		"bad key":       map[string]any{"\xff": 1},
		"struct":        struct{}{},
		"number float":  json.Number("1.0"),
		"number exp":    json.Number("1e3"),
		"number bigger": json.Number("9007199254740992"),
	} {
		if _, err := Canonical(v); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Canonical(int64(1)<<53 - 1); err != nil {
		t.Errorf("max safe integer rejected: %v", err)
	}
	for _, raw := range []string{`"\ud800"`, `"\udc00x"`, `"\ud800A"`, `{"a":1} x`, `1.5`} {
		v, err := ParseJSON([]byte(raw))
		if err == nil {
			_, err = Canonical(v)
		}
		if err == nil {
			t.Errorf("%s: accepted", raw)
		}
	}
	if _, err := ParseJSON([]byte(`"😀 \\ud800"`)); err != nil {
		t.Errorf("valid pair / escaped backslash rejected: %v", err)
	}
}
