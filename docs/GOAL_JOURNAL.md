# Durable goal and task journal

`control_plane_core.goals.DurableGoalStore` is the Ubuntu-hosted persistence foundation
for goals submitted by Codex on macOS. The Mac component is only a pinned-SSH
MCP client; it does not hold the authoritative goal database. Ubuntu uses SQLite with full synchronous commits,
owner-only database permissions, tenant-scoped identifiers, idempotent goal
submission, exact operation/target task records, and a per-goal hash-linked
event history. It contains no SSH, cloud, VirtualBox, or shell executor.

## Trust boundary

A goal is untrusted intent, not an executable plan. A planner must turn it into
typed operations registered by trusted adapters. Every task is initially
`pending_policy`; a policy decision is recorded separately. The journal rejects
generic `shell.exec` and `command.run` tasks and production/regulated dispatch.
An `auto_eligible` decision cannot be queued yet. An `approval_required` task
can enter the durable queue only after the injected Ed25519 verifier accepts a
single-use signed approval bound to its exact tenant, single target, operation,
environment, task ID, and plan digest. The signed record and its digest are
retained in the event chain. Queueing still does not authorize a worker or
permit execution.

The event chain is tamper-evident, not a cryptographic signature, remote
replication, backup, or immutable/WORM archive. Protect and back up the host
database; export evidence to the separately governed ledger when that
integration exists. SQLite is a single-host prototype and must not be placed on
a network filesystem or shared between regional workers. Fleet deployment
requires a transactional multi-tenant database, queue, HA, retention, backup,
and tenant-isolation testing.

## Current API surface

- `submit_goal(...)`: tenant/requester/idempotency-scoped goal, objective, and
  declared guardrails. A repeated idempotency key returns the original goal.
- `add_task(...)`: requires a complete `a2z-task-plan-v1` artifact whose
  operation, exact targets, and environment match the task. Ubuntu computes and
  stores the plan digest; caller-supplied digests are not accepted. Secret-like
  plan fields and oversized/malformed plans are rejected.
- `evaluate_infrastructure_task`: evaluates a pending task under an exclusive,
  expiring, token-fenced policy-evaluation lease against an
  independently signed autonomy profile and code-owned operation-risk catalog;
  an optional signed impact assessment is cryptographically checked against a
  separate root-managed estimator trust directory and the exact stored task,
  targets, operation, environment, and plan digest. Its digest is retained in
  the policy-decision event. Missing profiles/unknown operations deny, while
  high-impact VM lifecycle actions require approval. Routine eligibility needs
  a matching action/target/environment window in the signed profile; without
  one, the window is closed.
- `record_decision(...)`: persists the resulting classification and appends
  evidence; it always writes `execution_permitted: false`. An `auto_eligible`
  classification is rejected unless the exact signed autonomy envelope is
  reverified against the configured policy trust store, tenant, enabled state,
  and policy digest; the envelope is retained with the decision for later
  independent revalidation. This provenance alone does not queue or execute.
- `queue_task(...)`: verifies and consumes a task-bound signed approval for an
  approval-required non-production task; it leaves `execution_permitted` false.
- `queue_autonomous_task(...)`: for a routine `auto_eligible` task, re-verifies
  the retained signed profile and exact-task impact estimate, rechecks the
  stored plan, goal guardrails, active concurrency, current policy window, and
  code-owned operation contract, then records a standing-policy queue event.
  `claim_execution_lease(...)` and `issue_execution_grant(...)` revalidate
  either this standing-policy authorization or a signed operator approval.
  This source-level flow still does not make the task deployable: the worker
  API/service and signer boundary are not installed or Linux-validated.
- `claim_execution_lease(...)`: revalidates the retained authorization, grants one
  bounded, token-fenced lease, and increments a per-task fencing generation.
  At most one task per tenant may be leased/running/verifying at a time; each
  lease is at most 10 minutes and the hard-coded total task deadline is 30 minutes.
- `issue_execution_grant(...)`: revalidates the retained authorization and
  active fenced lease, requires a trusted signer and verifier injected by a
  separately protected service plus an enabled root-managed kill switch,
  restricts the grant to one target, and binds
  it to the lease-token digest and plan. Grants expire no later than the lease
  or five-minute plan cap. It is not exposed over MCP and does not dispatch work.
- `start_leased_task(...)`, `renew_execution_lease(...)`, and
  `begin_task_verification(...)`: `start_leased_task` is now an atomic
  one-time permit-consumption transition. It revalidates the authenticated
  runner-to-lease binding, signed approval, stored plan/digest, code-owned
  operation contract, signed grant/digest, runtime/lease expiry, circuit
  breaker, and root-managed kill switch inside the transaction; it marks that
  grant consumed and enters `running` exactly once. It does not call an
  adapter or claim an infrastructure change occurred. The authenticated runner
  identity must be supplied by a trusted local service boundary, not by a task
  submitter. Lease renewal and verification transitions remain journal-only.
- `record_runner_attestation(...)`: verifies a domain-separated Ed25519 receipt
  against a root-managed runner trust directory and the active task, target,
  operation, plan digest, runner identity, and fencing generation. Its digest
  must match the verification-start event. It stores deduplicated,
  tenant-scoped evidence and leaves the task in `verification`; a signed runner
  claim is not independent postcondition verification.
- `get_circuit_breaker(...)` and `reset_circuit_breaker(...)`: retain a
  tenant/target/operation breaker. A verified runner receipt reporting
  `failed`, `unknown`, or unexpected credential issuance opens it; grant
  issuance is then denied. Any unexpected target-side network activity also
  opens the breaker under the zero-network operation contract. Reset requires a fresh, single-use signed approval
  bound to the exact triggering task and an evidence digest. Success claims do
  not reset the breaker automatically.
- `Ed25519ExecutionGrantSigner` and `Ed25519ExecutionGrantVerifier`: provide
  root-key-protected signing and exact-scope, short-lived Ed25519 verification.
  `UnixExecutionGrantSigner` and the dedicated-identity signer service now
  provide a source-level local signing boundary pinned to one tenant, runner,
  target, operation, and runtime. It still trusts the authenticated API service
  to validate operator/policy authorization, and is not deployed or Linux-tested.
  `GovernedVirtualBoxWorker` now provides a one-shot coordinator over the
  mTLS worker API and the fixed adapter, but there is no installed worker
  service. The runner derives expected claims from authenticated live lease
  state—not from the grant submitter.
- `RunnerPreflight`: a non-executing worker-side library primitive obtains a
  live lease from an injected authenticated source, derives the expected grant
  claims itself, verifies plan digest/catalog/typed operation constraints, and
  enforces lease, grant, and plan deadlines. The journal's `start_leased_task`
  consumes the same grant atomically after rechecking authority. The mTLS API
  source supplies the authenticated lease/permit boundary; no worker API
  service, runner identity deployment, or Linux endpoint is installed.
- `ImpactAssessmentVerifier`: verifies a separate domain-separated Ed25519
  estimate signed by a trusted estimator, with a maximum 10-minute lifetime.
  It verifies exact task/plan scope and bounded resource/cost fields. No
  estimator implementation or signing key is included; absence or invalidity
  cannot make a task autonomously eligible.
- `RootManagedExecutionControl`: fails closed unless the Ubuntu host has a
  root-owned, group-read-only, current enablement window. The installer places
  a disabled default. Source checks it at grant issuance and immediately before
  the adapter's sole mutation verb; the adapter/worker are not installed or
  Linux-validated.
- `recover_expired_execution_lease(...)`: invalidates an expired token and
  blocks the task for review; it never retries because the side-effect outcome
  may be uncertain.
- `reconcile_late_runner_attestation(...)`: accepts a historically verified
  receipt only when it matches the authenticated runner, consumed grant, exact
  lease generation, target, plan digest, and grant-time window. A safe receipt
  resumes independent postcondition verification only; failed or out-of-
  contract evidence stays blocked and opens the circuit breaker. It never
  requeues or re-executes infrastructure work.
- `events(...)` and `verify_events(...)`: tenant-scoped history and hash-chain
  validation.

The goal/task interface is exposed by an Ubuntu-hosted stdio MCP gateway over a
Mac-side pinned-SSH bridge. The goal record therefore persists on Ubuntu across
Codex sessions and SSH reconnects. The journal and worker API source model
leases, authorization, grants, one-shot permit consumption, and receipt flow;
the Ubuntu gateway remains a request interface, not an unattended worker.
Lease methods are not exposed as general MCP tools. A deployable, isolated
worker service, confined grant signer, runner identity configuration, and
Linux end-to-end validation are still required before autonomous mutation.
