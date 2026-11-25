# State transitions

Authoritative rules live in [ADR 0001](../adr/0001-governance-and-evidence-contracts.md). Executable cases: `tests/contracts/`.

## Turn (derived from the event log)

```
turn_received -> policy_decision
policy_decision(deny)  -> turn_completed(outcome=denied)            disclosure: none (no sealing, intent, provider or release events allowed)
policy evaluation error -> policy_decision(deny, reason=policy_evaluation_failed) -> turn_completed(outcome=denied)
policy_decision(allow) -> usage_reserved -> context_sealed
context_sealed -> disclosure_intent -> evidence_ack(intent)         <- R1 gate
evidence_ack(intent) -> provider_accepted                           disclosure: disclosed
provider_accepted -> output_recorded(complete=true) -> evidence_ack(output)
evidence_ack(output) -> response_released                           <- R2 gate
response_released -> usage_settled -> turn_completed

any non-terminal state -> turn_interrupted   (provider error, store outage, crash recovery)
```

| Last durable event | Disclosure if interrupted | Client sees | Usage |
| --- | --- | --- | --- |
| before acked intent | none | error | reservation released |
| acked intent, no `provider_accepted` | **unknown** (treated as disclosed) | error | settled at reserved max |
| `provider_accepted`, no complete output | disclosed, output partial | error (no partial text) | settled at reserved max or provider-reported if known |
| complete output acked, not released | disclosed, output complete | error or retry of *delivery only* | settled |

Exactly one terminal event (`turn_completed` | `turn_interrupted`) per turn. `response_released` only precedes `turn_completed`.

## Evidence item retention (hold is a derived overlay)

```
active --(now >= retention_expires_at AND not held)--> disposal_pending   [sweep, records hold_epoch]
disposal_pending --(hold matches at any time before purge)--> active      [hold wins]
disposal_pending --(grace elapsed AND not held AND purge approved)--> purging   [begin_purge: tombstone, records hold_epoch]
purging --(hold matches)--> active                                         [hold wins; bytes still exist]
purging --(conditional delete, hold_epoch unchanged)--> disposed           [finish_purge, irreversible]
purging --(hold_epoch changed, no hold matches)--> disposal_pending        [restart under new epoch; never delete blind]
```

`held(item) = exists active hold h: matches(h, item)`. `disposed` has no outgoing transitions. A hold that would have matched an already-`disposed` item records `disposed_before_hold` in its report.

## Hold

```
active --(release by records_officer)--> released
```

Release removes only that hold's claim. Placement and release each take the next `hold_epoch` in a serialized transaction. Overlap: item stays held while any other active hold matches.

## Concurrency interleavings required to pass

| Case | Order | Required result |
| --- | --- | --- |
| A | hold placed, then sweep | item not a candidate; never pending |
| B | sweep marks pending, hold placed, purge attempted | item restored to active; purge refuses |
| C | sweep, purge, then hold placed | item disposed; hold reports `disposed_before_hold` |
| D | two holds overlap, release one | item still held; not a sweep candidate |
| E | two holds overlap, release both, expired | eligible; unheld control expires normally |
| F | purge begun (tombstoned), hold acknowledged, purge finish attempted | item restored; delete refused |
| G | purge begun, unrelated epoch change, finish attempted | no blind delete; purge restarts under new epoch |
