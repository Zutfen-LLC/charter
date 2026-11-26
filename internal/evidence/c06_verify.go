package evidence

import (
	"bytes"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

var c06Opaque = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,256}$`)

var c06Timestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)

// defaultRegistryModel is the documented default resolution for an omitted
// model selection (docs/model-routing-and-budget.md: "an optional `model_id`
// (default `det-a`)"). It is a code constant of this contract version, not
// mutable project routing configuration, so an offline verifier may hold the
// same expectation without reconstructing historical routing state.
const defaultRegistryModel = "det-a"

// verifyC06 implements versioned source-provenance rules without changing the
// historical contract for turns that do not opt into source binding.
func verifyC06(events []Event, objects map[string][]byte, full bool) (errs []string) {
	if len(events) == 0 {
		return nil
	}
	add := func(i int, s string) {
		prefix := ""
		if i >= 0 {
			prefix = fmt.Sprintf("seq %d: ", i)
		}
		errs = append(errs, prefix+"[C06] "+s)
	}
	received := payload(events[0])
	_, enabled := received["source_binding_version"]
	if !enabled {
		for i, e := range events {
			for _, k := range []string{"source_provenance_sha256", "source_authorized_at", "model_registry_id"} {
				if _, ok := payload(e)[k]; ok {
					add(i, "orphan source provenance marker")
				}
			}
			if str(e, "type") == "context_sealed" {
				entries, _ := payload(e)["sources"].([]any)
				for _, raw := range entries {
					s, _ := asObj(raw)
					if _, ok := s["external"]; ok {
						add(i, "orphan external source marker")
					}
				}
			}
		}
		return errs
	}
	if n, ok := integer(received["source_binding_version"]); !ok || n != 1 {
		add(0, "unsupported source binding version")
	}
	if model, exists := received["model_registry_id"]; exists {
		if s, ok := model.(string); !ok || !idRe.MatchString(s) {
			add(0, "model_registry_id must be an explicit model identifier")
		}
	}
	sealedAt := -1
	for i, e := range events {
		if str(e, "type") == "context_sealed" {
			sealedAt = i
			break
		}
	}
	if sealedAt < 0 {
		return errs
	} // a partial prefix may not yet have a seal
	sources, ok := payload(events[sealedAt])["sources"].([]any)
	if !ok {
		add(sealedAt, "sealed sources must be an ordered list")
		return errs
	}
	if p := str(received, "evidence_profile"); p != CurrentProfile && p != RetentionProfile {
		add(0, "source binding needs an explicit supported evidence profile")
	}
	externalFound := false
	sealed := payload(events[sealedAt])
	refs, _ := asRefList(sealed["objects"])
	lengths := map[string]int64{}
	for _, ref := range refs {
		lengths[ref.sha] = ref.bytes
	}
	var boundScope [6]string
	excerpts := make([]any, 0, len(sources))
	for _, raw := range sources {
		s, ok := asObj(raw)
		if !ok {
			add(sealedAt, "source entry must be an object")
			continue
		}
		n, valid := integer(s["bytes"])
		sha := str(s, "sha256")
		if size, ok := lengths[sha]; !valid || n < 0 || !ok || n != size {
			add(sealedAt, "C06 source byte length does not match sealed object")
		}
		data := objects[sha]
		if full && !utf8.Valid(data) {
			add(sealedAt, "source is not valid UTF-8")
		}
		rawExt, exists := s["external"]
		wantLen := 4
		if exists {
			wantLen++
		}
		if len(s) != wantLen {
			add(sealedAt, "source descriptor has unknown fields")
		}
		if !exists {
			excerpts = append(excerpts, map[string]any{"source_id": s["source_id"], "version": s["version"], "text": string(data)})
			continue
		}
		externalFound = true
		e, ok := asObj(rawExt)
		if !ok {
			add(sealedAt, "external source descriptor must be an object")
			continue
		}
		want := []string{"connector_id", "provider", "external_tenant_id", "site_id", "library_id", "document_id", "provider_version", "etag", "document_sha256", "delegated_subject", "custodian_id", "offset", "length", "extraction", "decision", "observed_at"}
		if len(e) != len(want) {
			add(sealedAt, "external source descriptor has missing or unknown fields")
		}
		for _, k := range want {
			if _, ok := e[k]; !ok {
				add(sealedAt, "external source descriptor has missing or unknown fields")
				break
			}
		}
		if str(e, "provider") != "sharepoint" || str(e, "extraction") != "utf8-byte-range-v1" || str(e, "decision") != "allow" || str(s, "source_id") != str(e, "document_id") {
			add(sealedAt, "external source identity or extraction binding is invalid")
		}
		if n, ok := integer(s["version"]); !ok || n != 0 {
			add(sealedAt, "external source version must be zero")
		}
		for _, k := range []string{"connector_id", "external_tenant_id", "site_id", "library_id", "document_id", "provider_version", "etag", "delegated_subject", "custodian_id"} {
			if !c06Opaque.MatchString(str(e, k)) {
				add(sealedAt, "external source identifier invalid")
			}
		}
		offset, offsetOK := integer(e["offset"])
		length, lengthOK := integer(e["length"])
		if !offsetOK || !lengthOK || offset < 0 || length <= 0 || length > 64<<10 || offset > (8<<20)-length || length != n || !shaRe.MatchString(str(e, "document_sha256")) {
			add(sealedAt, "external byte range or source digest invalid")
		}
		if str(e, "custodian_id") != str(received, "custodian_id") {
			add(sealedAt, "source custodian differs from admitted identity")
		}
		scope := [6]string{str(e, "connector_id"), str(e, "external_tenant_id"), str(e, "site_id"), str(e, "library_id"), str(e, "delegated_subject"), str(e, "custodian_id")}
		if boundScope == ([6]string{}) {
			boundScope = scope
		} else if boundScope != scope {
			add(sealedAt, "inconsistent external source scope")
		}
		excerpts = append(excerpts, map[string]any{"source_id": s["source_id"], "provider_version": e["provider_version"], "text": string(data)})
		observed := str(e, "observed_at")
		if !c06Timestamp.MatchString(observed) {
			add(sealedAt, "external observed_at must be UTC milliseconds")
		} else if _, err := time.Parse("2006-01-02T15:04:05.000Z", observed); err != nil {
			add(sealedAt, "source observation date is invalid")
		} else if observed > str(events[sealedAt], "recorded_at") {
			add(sealedAt, "source observation cannot follow context_sealed")
		}
	}
	if !externalFound {
		add(sealedAt, "source binding version 1 requires an external source")
	}
	// C06 replay identity is v3 and binds the ordered source descriptors. The
	// observation time and authorization decision are evidence, not identity.
	fingerprintSources := make([]any, 0, len(sources))
	for _, raw := range sources {
		s, ok := asObj(raw)
		if !ok {
			continue
		}
		copySource := make(map[string]any, len(s))
		for k, v := range s {
			copySource[k] = v
		}
		if rawExt, ok := s["external"]; ok {
			if ext, ok := asObj(rawExt); ok {
				copyExt := make(map[string]any, len(ext))
				for k, v := range ext {
					if k != "observed_at" && k != "decision" {
						copyExt[k] = v
					}
				}
				copySource["external"] = copyExt
			}
		}
		fingerprintSources = append(fingerprintSources, copySource)
	}
	first := events[0]
	fingerprintIdentity := map[string]any{"v": 3, "tenant_id": str(first, "tenant_id"), "project_id": str(first, "project_id"),
		"matter_id": str(first, "matter_id"), "custodian_id": str(received, "custodian_id"), "input": received["input"],
		"sources": fingerprintSources, "model_id": str(received, "model_registry_id")}
	canonicalIdentity, fingerprintErr := Canonical(fingerprintIdentity)
	if fingerprintErr != nil || str(received, "request_fingerprint") != SHA256(canonicalIdentity) {
		add(0, "C06 stable v3 request fingerprint mismatch")
	}
	canonicalSources, err := Canonical(sources)
	if err != nil {
		add(sealedAt, "sealed sources are not canonicalizable")
		return errs
	}
	if full {
		in, _ := asRef(received["input"])
		pin := last(events, "policy_decision")
		var model string
		if pin >= 0 {
			d, _ := asObj(payload(events[pin])["destination"])
			model = str(d, "model_id")
		}
		input := objects[in.sha]
		rendered, err := Canonical(map[string]any{"model": model, "input": string(input), "excerpts": excerpts})
		if model == "" || !utf8.Valid(input) || err != nil || !bytes.Equal(rendered, objects[str(sealed, "request_sha256")]) {
			add(sealedAt, "exact rendered request differs from sealed input or excerpts")
		}
	}
	provenance := SHA256(canonicalSources)
	latestAuth := str(events[sealedAt], "recorded_at")
	for i, e := range events {
		typ, ep := str(e, "type"), payload(e)
		if typ == "usage_reserved" {
			if str(ep, "accounting_version") != budgetVersion || !idRe.MatchString(str(ep, "registry_model")) {
				add(i, "C06 usage reservation requires C05 governed accounting")
			} else if requested, ok := received["model_registry_id"].(string); ok {
				// Attributable model identity: the governed accounting
				// reservation must bind the same registry model the turn
				// explicitly requested. Registry identifiers are never
				// provider-native destination model identifiers, so the
				// policy destination is deliberately not compared here.
				if str(ep, "registry_model") != requested {
					add(i, "C06 reserved registry model differs from the explicitly requested registry model")
				}
			} else if _, malformed := received["model_registry_id"]; !malformed {
				// No model was explicitly requested: the reservation must
				// bind the documented default resolution.
				if str(ep, "registry_model") != defaultRegistryModel {
					add(i, "C06 reserved registry model must be the documented default resolution")
				}
			}
		}
		if typ == "output_recorded" || typ == "response_released" {
			if str(ep, "source_provenance_sha256") != provenance {
				add(i, "output and release must bind the complete sealed source provenance")
			}
		}
		if typ == "disclosure_intent" || typ == "provider_accepted" || typ == "response_released" {
			ts := str(ep, "source_authorized_at")
			if !c06Timestamp.MatchString(ts) {
				add(i, typ+".source_authorized_at must be UTC milliseconds")
			} else if _, err := time.Parse("2006-01-02T15:04:05.000Z", ts); err != nil {
				add(i, typ+".source_authorized_at is invalid")
			} else if ts > str(e, "recorded_at") || ts < latestAuth {
				add(i, typ+".source_authorized_at is out of order")
			} else {
				latestAuth = ts
			}
		}
	}
	return errs
}
