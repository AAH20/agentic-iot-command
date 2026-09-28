# Trusted task impact assessments

Cost and blast-radius limits are useful only when their input is independently
trusted and bound to the reviewed plan. The goal gateway therefore accepts an
optional signed assessment when evaluating a task; it does not accept raw cost
or resource-count fields from Codex.

## Signed contract

The payload follows [`schemas/impact-assessment.schema.json`](../schemas/impact-assessment.schema.json).
The Ed25519 signature covers canonical UTF-8 JSON with sorted keys, compact
separators, ASCII escaping, and no NaN values:

```json
{"domain":"a2z.impact-assessment.v1","assessment":ASSESSMENT}
```

The assessment binds the tenant, task UUID, operation, exact ordered target
list, non-production environment, and server-computed plan SHA-256. It also
contains the affected-resource count, estimated incremental cost in integer
micro-USD, estimator identity, generation time, and expiry. The verifier
rejects wildcard/duplicate targets, stale assessments, expired/future-dated
records, estimates outside fixed bounds, and any mismatch with the stored
task. The maximum assessment lifetime is ten minutes.

The envelope is submitted only as the optional `impact_assessment` object to
`evaluate_infrastructure_task`. The gateway verifies the signature against
`/etc/a2z-control-plane/impact-assessment-trust/<key_id>.pem`, validates the
scope against the task loaded from SQLite (never MCP arguments), and records
the assessment digest in the decision event. A missing estimate leads to
approval-required; an invalid or untrusted supplied assessment is denied.
Neither result grants execution. A high-impact operation still requires human
approval even when the estimate is valid and under budget.

## Estimator trust and limits

The trust directory is separate from approval and autonomy-policy trust.
Public keys must be installed and owned by root, inside the root-managed,
non-group/other-writable directory. The signing key belongs to a separately
reviewed estimator or HSM-backed service; it must not be copied to Codex, the
goal gateway, this repository, or an execution runner. No estimator or private
key is included here. Do not add a key until the estimator's data sources,
coverage, conservative uncertainty handling, plan binding, key lifecycle, and
failure behavior have been reviewed.

This verifier establishes provenance, freshness, and binding; it does not
prove that an estimator is accurate. Unknown pricing, incomplete dependency
graphs, stale provider data, or uncertainty must be represented as unavailable
by the estimator, not as a zero-cost/zero-blast estimate. Provider adapters
must be tested against independent ground truth before their assessments can
inform unattended policy. The live MCP evaluator currently keeps the
maintenance window closed, and the goal journal has no worker, scheduler, or
mutation executor; this feature does not enable autonomous changes.
