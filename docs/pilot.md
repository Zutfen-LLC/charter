# Charter governance pilot

## Decision to test

Can a customer-operated control plane enforce who can use which AI models and preserve the exact work done on a held matter, even after the ordinary workspace view changes? The pilot tests technical preservation and export, not legal sufficiency or full eDiscovery.

## Boundaries

- Use synthetic records, two isolated projects, separate user and records roles, test identity, and two deterministic model adapters. Start without external credentials, external model traffic, or a fork.
- Add a read-only delegated SharePoint adapter and approved model endpoints only in dedicated test environments. Run the drill with reproducible fixtures; identify any mocked boundary in the results. Test actual storage protection before qualifying preservation.
- The workspace is the normal working copy. Evidence is a separate, restricted record, not a second UI for accessing otherwise restricted work. Capturing a source excerpt does not preserve the external library.
- Charter owns authorization, permitted egress, usage reservation, durable capture, hold and export. Desktop packaging, arbitrary tools, provider failover, client-side model credentials, other document connectors, and legal-platform ingestion are out of scope.

## Work order

| Issue | Outcome | Depends on |
| --- | --- | --- |
| [#1](https://github.com/Zutfen-LLC/charter/issues/1) | Review governance, threat model and evidence contract | Start now |
| [#2](https://github.com/Zutfen-LLC/charter/issues/2) | Local scaffold, fixtures, and CI | Start now; follow #1 for durable schema |
| [#3](https://github.com/Zutfen-LLC/charter/issues/3) | Identity, project isolation, role separation | #1, #2 |
| [#4](https://github.com/Zutfen-LLC/charter/issues/4) | Evidence capture path and storage enforcement | #1, #2 |
| [#5](https://github.com/Zutfen-LLC/charter/issues/5) | Governed routing, budget and usage | #3, #4 |
| [#6](https://github.com/Zutfen-LLC/charter/issues/6) | Permission-bound, versioned document context | #3, #4 |
| [#7](https://github.com/Zutfen-LLC/charter/issues/7) | Hold, retention and release | #3, #4 |
| [#8](https://github.com/Zutfen-LLC/charter/issues/8) | Scoped export and offline verification | #7; format can start after #1 |
| [#9](https://github.com/Zutfen-LLC/charter/issues/9) | Integrated drill and go/no-go | #5, #6, #7, #8 |
| [#10](https://github.com/Zutfen-LLC/charter/issues/10) | Optional ZCode evaluation | After #9; not a pilot gate |

## Acceptance drill

1. A synthetic user performs work in a held matter using versioned source context. A second permitted model completes another turn. A local-only project refuses the hosted route.
2. Change and delete the source; remove the visible chat and project and revoke the custodian. Confirm normal users lose access and that only the appropriate records roles can operate on held evidence.
3. Export and independently verify the original inputs, actual context, outputs/artifacts, policy decisions and custody metadata. Fail the verify step for a missing or changed object.
4. Show that releasing one of two holds preserves evidence and that unheld controls expire. Inject concurrent hold/expiry and storage failures. Record whether any disclosure occurred and show no successful response can escape without the required evidence.
5. Reproduce from a clean checkout at a pinned commit. Report the exact scope demonstrated, what was mocked, open gaps and the go/no-go decision. An unavailable non-mock storage or integration test is a recorded gap, not a pass.

The routing and budget pilot boundary is specified in [C05 model routing and accounting](model-routing-and-budget.md). This does not expand retained storage qualification or authorize real inference egress.
