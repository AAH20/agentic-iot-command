# Governed autonomy control model

The target operating model is goal-driven delegation: the operator sets an
outcome and signed governance envelope once; the control plane continuously
observes, plans, and executes only routine actions that fit that envelope.
Codex on macOS is the goal-setting and oversight interface, not a persistent
remote shell. Critical, irreversible, security-boundary, production, and
out-of-policy decisions return to the operator. The current implementation is
still a policy evaluator, not a remote executor: it does not yet dispatch
actions or mint credentials.

## Goal-to-execution control path

```text
Mac Codex goal
  → durable goal/task record on the control plane
  → observed state + typed proposed operations
  → deterministic operation contract and risk classification
  → autonomy policy evaluation
      ├─ routine + exact signed rule + inside limits → policy-classified auto-eligible
      ├─ high impact / out of scope / limits exceeded → human approval queue
      └─ forbidden / unknown / revoked / expired → deny
  → isolated regional runner with short-lived capability
  → canary → health check → bounded rollout → stop/circuit-break on anomaly
  → postcondition verification + rollback decision + durable evidence
```

Codex is the goal-setting and oversight interface. In the target architecture,
a persistent control-plane service and workers perform scheduled execution,
so work can continue when a Codex chat or the Mac UI is not active. Ubuntu is
the first lab control-plane node, not a universal root credential or a single
SSH hop to every device. “Control the fleet” means an inventory-backed set of
typed, independently governed adapters for each platform—not unrestricted
access to every host. Fleet scale requires regional queues/workers,
provider-native adapters, partitioned just-in-time credentials, and a highly
available control plane.

## Decision classes

`AutonomyPolicyEngine` produces one of three policy outcomes:

- `auto_eligible`: exact routine action contract and exact target allowlist
  match a current verified policy; operation is idempotent, reversible,
  verifiable, not privileged, within an open maintenance window, and within
  target/batch/concurrency limits.
- `approval_required`: the action is known but a standing rule or a safety
  precondition is missing. High impact, provisioning, decommission, security
  boundary changes, production, and regulated actions are never auto-eligible.
- `deny`: unknown operation, expired/revoked profile, tenant mismatch, malformed
  plan digest, generic shell/command operation, or explicitly denied action.

The operation's risk and safety properties come from trusted adapter metadata,
not model output or caller-supplied fields. The policy request includes a
SHA-256 plan digest; eligibility binds to that exact planned change. Any change
to operation, targets, arguments, plan or policy requires reevaluation. Signed
profiles also set maximum affected resources and estimated incremental cost
in integer micro-USD, globally and per action. Missing or over-budget estimates
cannot be auto-eligible. Estimates must come from a trusted adapter/plan
analyzer bound to the same plan digest; a model-provided number is not
authority. Providers with uncertain or unavailable cost data must classify the
estimate as unavailable and require approval.

## Current enforcement status

The evaluator, strict Ed25519 profile loader, Ubuntu-hosted durable goal/task journal,
MCP task-policy evaluation with exclusive, expiring policy-review leases,
single-use task-bound approval queueing, and fenced execution-lease state
transitions now establish part of this contract. The
code-owned VirtualBox operation catalog classifies VM start and graceful ACPI
shutdown as high impact; neither can become auto-eligible. It now also models
one routine lab operation, `virtualbox.vm.set_demo_description`, with a
code-fixed target count, label, powered-off precondition, zero-cost impact cap,
and exact rollback value. Its typed-plan validator rejects any changed label
or expanded scope. Oracle documents that a VM description has no effect on
functionality and that `modifyvm` requires a powered-off VM ([description
semantics](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/working-with-vms.html),
[`modifyvm` requirements](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/vboxmanage.html)).
The operation is only eligible for policy classification; an auto-eligible
decision now retains the exact Ed25519-signed autonomy profile after the
journal independently re-verifies its tenant and digest. This preserves policy
provenance but still does not queue or execute the task. No adapter or worker
is connected and no VM has been relabeled. The sample
[`policies/autonomy-defaults.json`](../policies/autonomy-defaults.json) has
autonomy disabled and no auto rules. `auto_eligible` is only a policy
classification, not a worker lease or runner token; `execution_permitted`
remains false. The journal can now queue a routine `auto_eligible` task only
after re-verifying its retained signed profile and exact-task impact estimate,
then rechecking the plan, goal guardrails, concurrency, maintenance window, and
operation contract. That queue is not executable: lease acquisition still
requires signed operator approval, and lease transitions are not connected to a
runner or enforced at an executor. Critical tasks still require an exact signed
approval. A
mutation executor, current-state precondition checks, runner-side signed
receipt production, and worker-side kill switch remain unimplemented. The
durable journal breaker now opens on a signature-verified runner receipt reporting failure,
unknown outcome, or unexpected credential issuance; it requires a fresh signed
approval bound to evidence to reset, but is not yet enforced at a worker. The
MCP evaluator can verify an optional signed impact assessment against a
separate trust directory, but no estimator or signing key is deployed.
Maintenance windows must be included in the signed autonomy profile and are
matched against exact action/target/environment and full task runtime. No
window exists in the disabled default profile, and no routine work can be
auto-authorized until a trusted estimator and narrowly scoped signed profile are
deployed. Do not wire the
evaluator directly to SSH, a shell, VBoxManage mutation commands, Terraform
apply, or cloud APIs. See [`GOAL_JOURNAL.md`](./GOAL_JOURNAL.md) and
[`SIGNED_AUTONOMY_POLICY.md`](./SIGNED_AUTONOMY_POLICY.md).

The first real policy profile should be signed out of band and narrowly scoped
to one lab tenant, one registered disposable VM, one fixed reversible action,
one active operation at a time, an explicit time window, and verified rollback
and health predicates. Broader targets or actions must be separately approved
and evaluated. Preserve a global kill switch and enforce it at both scheduler
and worker.

## Human-in-the-loop rule

The operator should not approve every routine action. The operator sets a
standing policy and sees summaries, exceptions, and evidence. Individual
approval is required for high-impact, irreversible, security-boundary,
production, regulated, out-of-policy, or circuit-breaker events. Standing
policy is itself a signed governance decision with an owner, scope, expiry, and
revocation path; it must never be inferred from a chat instruction or voice
transcript.

## Governance envelope for fleet delegation

Before any execution worker is enabled, the owner must be able to set and
review, per tenant and environment: enrolled accounts/projects/clusters and
explicit exclusions; allowed adapter operations and target labels; maintenance
windows; maximum affected resources and estimated incremental cost; batch and
concurrency limits; canary size; health and postcondition thresholds; retry and rollback limits; required
approvers; notification/escalation routes; policy expiry; and emergency stop
behavior. Resource and cost estimates must come from a trusted adapter or
plan analyzer and bind to the exact plan digest. Policies must support
narrower overrides, never broader implicit inheritance. The effective
envelope is the intersection of the signed owner
policy, the control-plane baseline, and the adapter's hard-coded safety
contract. Missing, conflicting, stale, or unverifiable controls mean no
execution.

The intended operator experience is one goal plus a standing governance
envelope, not one approval per routine operation. Codex may autonomously
decompose the goal and request typed operations, but only the service may
authorize them against observed state and the envelope. Approval prompts are
reserved for decisions the envelope classifies as critical or for exceptions;
the operator still receives progress, exceptions, and an evidence-backed
completion report. This is a target design, not a claim that the present code
has an unattended scheduler or mutation capability.
