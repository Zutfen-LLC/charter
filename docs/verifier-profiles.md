# Verifier profiles

The verifier exposes three compatibility modes through the same semantics:

- **Legacy**: historical logs may use `input_summary` and omit `storage_level`. A summary is descriptive only and must never be represented as byte-exact input. Legacy receipt identifiers remain required on acknowledgements.
- **Structural**: validates event structure, hash chain, lifecycle and cross-event identities without loading object bytes. Use `VerifyStructure`.
- **Complete**: applies structural checks and validates every referenced object digest and length. Use `VerifyFull` with a non-nil object map. Current logs record the actual routed destination consistently in policy, intent and provider acceptance; successful completion follows usage settlement.

All modes reject malformed acknowledgements, actor attribution inconsistent with admission/service activity, and an under-settled `reserved_max` disclosure. Existing golden event bytes are retained unchanged; `storage_level` remains optional for compatibility, but if present must be nonempty text.
