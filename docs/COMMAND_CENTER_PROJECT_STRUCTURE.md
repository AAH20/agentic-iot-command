# Command-Center Project Structure

## Architectural choice

Build a federated, policy-governed operations center: one coherent operational
picture, with regional execution cells and independently bounded management
domains. This borrows the interoperability and decision-support intent of
command-and-control architectures; it is not a military system and does not
create a universal remote-control channel.

The UI presents state and collects human intent/approval. It does not mint
privileges. Hermes and other agents analyze, coordinate, and propose typed
plans. The deterministic policy/approval/IAM-PAM path decides whether a plan
may run. Short-lived regional runners execute only exact, approved plans;
independent verifiers and the evidence ledger close the loop.

## Target repository layout

```text
a2z-command-center/
├── apps/
│   ├── operations-center/       # shared inventory, risk, task picture
│   ├── operator-cli/            # narrow, auditable workflows
│   └── reporting/               # evidence, compliance, cost, resilience
├── platform/
│   ├── api-gateway/             # authn, tenant routing, rate limits
│   ├── goals-and-plans/         # goal journal, typed plans, cancellation
│   ├── policy/                  # policy administration and decision
│   ├── approvals/               # human approval, dual control, break-glass
│   ├── identity-pam/            # workload identity, JIT, session records
│   ├── orchestration/           # bounded scheduling/delegation; no authority
│   ├── inventory-graph/         # canonical assets, relations, drift
│   ├── evidence/                # append-only ledger, replay, export
│   ├── model-gateway/           # approved providers, data rules, budgets
│   └── skill-registry/          # scan, review, pin, promote, revoke
├── agents/
│   ├── supervisor/
│   ├── virtualization/
│   ├── cloud/
│   ├── kubernetes/
│   ├── identity-and-pam/
│   ├── compliance-and-cost/
│   └── verifier/                # proposes checks; independent verifier is separate
├── connectors/
│   ├── virtualization/          # VirtualBox, KVM/Proxmox, VMware, CloudStack
│   ├── cloud/                   # AWS, Azure, GCP; regional providers later
│   ├── platforms/               # Kubernetes, OpenShift, Terraform/OpenTofu
│   ├── identity-and-pam/        # IdPs, workload identity, PAM products
│   └── access/                  # pinned SSH; supervised RustDesk boundary
├── execution/
│   ├── regional-runners/        # short-lived, isolated workers
│   ├── adapters/                # fixed typed operations per platform
│   ├── computer-use-sandbox/    # optional disposable GUI environment
│   └── independent-verifiers/   # read-only postcondition observation
├── contracts/
│   ├── schemas/                 # goal, plan, identity, grant, evidence
│   ├── events/                  # versioned event contracts
│   └── api/                     # OpenAPI and connector interfaces
├── policies/
│   ├── autonomy/                # action/risk classes and owner envelopes
│   ├── iam-pam/
│   ├── tenant-and-region/
│   ├── model-routing-and-data/
│   ├── skills-and-tools/
│   └── computer-use/
├── deploy/
│   ├── local-lab/
│   ├── central-control-plane/
│   ├── regional-cell/
│   └── backup-and-recovery/
├── tests/
│   ├── unit-and-contract/
│   ├── connector-conformance/
│   ├── policy-and-tenant-isolation/
│   ├── adversarial-agent-and-skill/
│   ├── chaos-and-recovery/
│   └── scale-and-benchmark/
└── docs/
    ├── architecture/
    ├── threat-models/
    ├── operator-runbooks/
    ├── data-and-evidence/
    └── deployment-guides/
```

This is the target product organization, not an instruction to split the
current prototype into dozens of services. Begin with a modular core and
contract-tested boundaries. Split deployables only when a distinct trust
boundary, scaling need, availability requirement, or independent release cycle
justifies it. Keep the existing handoff package and reference implementation
as the source of truth while adding modules incrementally.

## Runtime and trust-boundary layout

```text
Operator / Operations Center
       │ goals, shared picture, critical approvals
       ▼
Governance Control Plane ───── Model / Skill supply chain
       │ signed exact-plan grants
       ▼
Regional execution cell(s)
       │ narrowly scoped adapters
       ▼
VirtualBox / datacenter / cloud targets
       │
       └── read-only independent verification → tenant evidence ledger
```

- **Operations center:** dashboards, task timeline, plan diff, impact, health,
  approval prompts, stop controls, evidence explorer. Views are filtered by
  tenant/role and display freshness and uncertainty rather than hiding them.
- **Governance plane:** goals, typed plans, deterministic policy, approval,
  identity/PAM, autonomy envelope, and evidence references. It is the only
  authority that can request a grant.
- **Agent/model/skill plane:** agents have per-run workload identities and
  bounded tools. Model and skill services receive classification-approved
  inputs, but no infrastructure credentials. See
  `HERMES_SWARM_GOVERNANCE.md`.
- **Regional execution cells:** outbound-authenticated, tenant/region-scoped
  workers use short-lived plan-bound capabilities. No open inbound SSH or
  remote desktop fleet-control channel. A disconnected cell may perform only
  actions already permitted by a signed, unexpired local envelope; otherwise
  it stops and reports when connectivity returns.
- **Verifier/evidence plane:** verification is performed through a distinct
  read-only identity where possible. Preserve a tamper-evident chain of
  identity, plan, policy, approval, grant, execution, observation, and outcome.

Use Zero Trust principles: authorize each subject and device for each resource;
network location alone never establishes trust. This is especially important
for multi-cloud service identities and remote administration. See NIST SP
800-207 and SP 800-207A.

## Canonical operational object model

Every asset, observation, goal, plan, decision, grant, session, and evidence
record should carry stable IDs and explicit tenant, region, source identity,
timestamp, freshness, confidence, data classification, and provenance. Keep
vendor-specific fields in versioned connector extensions; do not erase source
semantics when normalizing. The evidence graph links:

`goal → observation → plan → impact → policy decision → approval → JIT grant →
runner receipt → independent verification → evidence record`.

No agent should infer authorization from an inventory relationship, dashboard
button, model response, skill instruction, or successful prior action.

## Delivery sequence

1. **Keep today's prototype intact:** document boundaries and contracts; test
   with synthetic inventory and fake transports.
2. **Ubuntu/VirtualBox observer slice:** pinned-SSH read-only enrollment,
   baseline comparison, identity and evidence. No worker or mutation.
3. **One lab canary:** only after a named disposable VM is selected; fixed
   metadata operation, signed plan/approval, independent verification, stop and
   recovery tests.
4. **Regional/cloud observation:** enroll one account/site/region at a time;
   establish quotas, data residency, tenant isolation, and connector conformance.
5. **Bounded production operations:** only after PAM/JIT, isolated runners,
   verifier separation, rollback, monitoring, and kill-switch tests pass.
6. **Fleet scale:** synthetic 10k-asset tests, bounded fan-out, fair scheduling,
   regional failure tests, and verified per-tenant isolation before claiming
   thousands-device readiness.

Define measurable outcomes for every phase: inventory accuracy, eligible task
completion, policy/approval correctness, evidence completeness, recovery,
cost-per-verified-change, and unauthorized actions (target zero). Do not
optimize for raw agent count or number of connected devices.

## Explicit exclusions

This structure does not authorize a hidden RAT, stealth persistence, credential
harvesting, unauthorized access, lateral movement, or connection to classified
networks. RustDesk is for explicit human-supervised GUI access; use the governed
API/runner path for automation. Remote administration software is privileged
infrastructure and needs a named owner, approved deployment, MFA/workload
identity, narrow scope, session/audit logging, and revocation.

For the detailed Agentic_IoT_Command OSS charter and Mermaid designs for sensor fusion,
edge deployment, and data/command separation, see
[`OPSATLAS_ARCHITECTURE.md`](./OPSATLAS_ARCHITECTURE.md). For energy-to-compute,
facility/IT operations workflows, and operational procedures, see
[`ENERGY_TO_COMPUTE_OPERATIONS.md`](./ENERGY_TO_COMPUTE_OPERATIONS.md).
For modular UI composition, key custody, and commercial module boundaries,
see [`OPSATLAS_UI_UX_AND_COMMERCIAL_BOUNDARIES.md`](./OPSATLAS_UI_UX_AND_COMMERCIAL_BOUNDARIES.md).
