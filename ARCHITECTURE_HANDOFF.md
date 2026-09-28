# A2Z Agentic Infrastructure Control Plane — Codex Handoff

## 0. Mission

Build a standards-based, security-first control plane that demonstrates and eventually packages autonomous operations across:

- macOS operator workstations and Android voice endpoints
- Ubuntu 26.04 operations hosts
- Proxmox/KVM, VMware, VirtualBox, and CloudStack
- Kubernetes and OpenShift
- Terraform/OpenTofu infrastructure-as-code
- OPA/Rego and compliance-as-code
- IAM, PAM, workload identity, service accounts, and AI-agent identity
- AWS, Azure, Google Cloud, Alibaba Cloud, and Huawei Cloud
- n8n and A2Z SOC integration workflows
- evidence, audit, cost, resilience, and board-level risk reporting

The system must let a human speak an intent, let agents inspect and plan, require policy-based authorization before mutation, execute through scoped credentials, verify the outcome, and produce evidence that another operator can replay.

This is an operational control plane, not a universal super-admin backdoor. Any action against systems the operator does not own or have explicit authorization to administer is out of scope.

## 1. Design outcomes

The operator-facing Agentic_IoT_Command architecture and federated asset/telemetry context
are specified in [`docs/OPSATLAS_ARCHITECTURE.md`](./docs/OPSATLAS_ARCHITECTURE.md).
Its end-to-end energy-to-compute model, full data-center workflows, procedure
templates, metrics, and phased acceptance gates are specified in
[`docs/ENERGY_TO_COMPUTE_OPERATIONS.md`](./docs/ENERGY_TO_COMPUTE_OPERATIONS.md).
The modular UI, MasterKeys/key-custody model, and OSS/commercial entitlements
are specified in
[`docs/OPSATLAS_UI_UX_AND_COMMERCIAL_BOUNDARIES.md`](./docs/OPSATLAS_UI_UX_AND_COMMERCIAL_BOUNDARIES.md).

### 1.1 Operator outcome

An operator wearing smart glasses or using an Android device can ask Codex Voice on the macOS workstation:

> “Show me every cluster with a critical identity drift, explain the business impact, prepare a Terraform remediation plan, and wait for my passkey approval before applying anything.”

The system returns a concise spoken summary, a visual topology, the exact plan, policy results, expected cost and blast radius, and a second-factor approval request.

### 1.2 Agent outcome

Agents are specialized, scoped, replaceable workers. They do not receive broad standing credentials. They communicate using typed requests and signed evidence envelopes.

### 1.3 Enterprise outcome

The customer receives cross-vendor IAM/PAM, agent governance, infrastructure compliance, and replayable evidence without replacing every existing vendor.

### 1.4 Founder and commercial outcome

The open-source layer creates provider interoperability. The commercial layer owns policy orchestration, evidence intelligence, managed controls, certified connectors, agent governance, and operational support.

## 2. Non-goals and hard boundaries

- No unauthorized access, scanning, exploitation, credential harvesting, or lateral movement.
- No bridge into JWICS or any classified network.
- No collection or retention of intelligence data without legal authority.
- No unreviewed destructive production mutation.
- No hidden administrator channel.
- No global pool of customer raw video, biometrics, secrets, or financial data.
- No claim that a clean scanner result proves a skill is safe.
- No direct production access from the Mac developer shell when an isolated runner is available.
- No use of voice as the sole approval factor for high-impact actions.

## 3. Operating topology

```text
Android / smart glasses
  └── audio input/output and emergency approvals

macOS workstation
  ├── ChatGPT/Codex desktop Voice
  ├── human approval console
  ├── optional Hermes swarm supervisor (proposal-only; no standing infra credentials)
  ├── browser and visual dashboards
  ├── Tailscale client
  ├── read-only operator tools / pinned SSH inventory connector
  └── RustDesk client for human-supervised GUI access only

Ubuntu operations host
  ├── agent gateway
  ├── model-routing gateway (approved routes only; no infra credentials)
  ├── skill registry and quarantine/promote pipeline
  ├── policy decision point
  ├── isolated execution runners
  ├── Terraform/OpenTofu
  ├── kubectl/oc
  ├── Proxmox/VMware/CloudStack clients
  ├── cloud provider clients
  ├── telemetry and evidence store
  ├── local skill store with approval ledger
  └── isolated ephemeral GUI desktop adapter (optional, policy-gated)

Private datacenter
  ├── Proxmox/KVM
  ├── VMware
  ├── VirtualBox lab
  ├── CloudStack
  ├── Kubernetes/OpenShift
  └── IAM/PAM/VMS/SIEM systems

Cloud accounts
  ├── AWS
  ├── Azure
  ├── GCP
  ├── Alibaba Cloud
  └── Huawei Cloud
```

Use a private overlay such as Tailscale/WireGuard for operator access. Do not expose SSH, RDP, Proxmox, Kubernetes, or cloud management ports directly to the Internet. The Mac can be a bastion where required, but direct private-overlay access to the Ubuntu host is preferred.

For the current reference implementation, the Mac can collect limited Linux
host and VirtualBox VM inventory through the opt-in pinned SSH connector
described in `docs/REMOTE_ACCESS_OPTIONS.md`, compare it against an
operator-managed baseline, and record the comparison in the evidence chain.
This is the first enrollment slice, not a fleet controller. Build outward in
this order: prove identity/inventory/evidence on the existing VirtualBox lab;
add read-only adapters for the other hypervisors and orchestration stacks;
establish a tenant/region-aware fleet inventory and policy plane; then add
isolated, provider-native execution runners behind the governance envelope.
RustDesk is a separate, operator-present GUI path, not an agent control API.
The current live connector does not enable mutation; production changes still
require isolated runners, provider-specific least-privilege identity, signed
plan approval, verification, and evidence.

## 4. Trust zones

### Zone A — Public discovery

Untrusted web pages, skills.sh results, GitHub repositories, package registries, issue trackers, and model outputs.

### Zone B — Quarantine

Downloaded skills and source artifacts. No execution, no credentials, no network except controlled source retrieval.

### Zone C — Development

Local code and test data. No production credentials. Network access is allowlisted.

### Zone C1 — Agent and model supply chain

Hermes runtime images, approved skill artifacts, model-routing policy, and
provider endpoints. Skills are digest-pinned and promoted through review;
models receive only classification-approved, minimized prompts. Neither the
runtime nor model gateway has infrastructure credentials or grants authority.

### Zone D — Control plane

Identity registry, policy engine, approval system, evidence ledger, inventory graph, and agent router.

### Zone E — Execution runners

Short-lived, disposable environments that execute approved plans. Each runner receives one task-specific capability token.

### Zone E1 — Computer-use sandbox

Disposable desktop/VM with allowlisted applications and egress, isolated from
host files, clipboard, credential stores, and general network access. It is a
separate adapter subject to the same policy and approval point; API adapters
remain preferred.

### Zone F — Customer environments

Private cloud, datacenter, and cloud-provider accounts. Customer keys, data, logs, and retention policies remain tenant-scoped.

### Zone G — Classified or regulated enclave

Separate build, release, personnel, facility, and authorization processes. No automatic connection from the commercial environment.

## 5. Repository structure

The following is the eventual product-level target tree, not a mandate to
create every service immediately. Begin with contract-tested modules and split
deployables only at justified trust, scale, availability, or release
boundaries. The current source prototype remains the baseline; see
[`docs/COMMAND_CENTER_PROJECT_STRUCTURE.md`](./docs/COMMAND_CENTER_PROJECT_STRUCTURE.md)
for the recommended command-center layout, runtime topology, object model, and
incremental delivery sequence.

```text
a2z-control-plane/
├── README.md
├── AGENTS.md
├── SECURITY.md
├── THREAT_MODEL.md
├── GOVERNANCE.md
├── LICENSE
├── NOTICE
├── CODEOWNERS
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── skill-scan.yml
│   │   ├── policy-test.yml
│   │   ├── security-scan.yml
│   │   └── release.yml
│   └── dependabot.yml
├── docs/
│   ├── architecture/
│   ├── runbooks/
│   ├── threat-models/
│   ├── api/
│   ├── policy-reference/
│   ├── operator-guides/
│   └── commercial/
├── schemas/
│   ├── identity-event.json
│   ├── privilege-event.json
│   ├── agent-action.json
│   ├── authorization-request.json
│   ├── evidence-envelope.json
│   ├── change-plan.json
│   ├── approval.json
│   └── connector-manifest.json
├── services/
│   ├── api-gateway/
│   ├── identity-registry/
│   ├── tenant-manager/
│   ├── asset-inventory/
│   ├── relationship-authorizer/
│   ├── policy-decision-point/
│   ├── policy-administration-point/
│   ├── policy-information-point/
│   ├── access-request-service/
│   ├── approval-service/
│   ├── credential-broker/
│   ├── workload-identity-broker/
│   ├── session-gateway/
│   ├── privileged-command-gateway/
│   ├── agent-tool-gateway/
│   ├── plan-service/
│   ├── execution-orchestrator/
│   ├── verification-service/
│   ├── drift-detector/
│   ├── evidence-ledger/
│   ├── graph-query-service/
│   ├── cost-service/
│   ├── notification-service/
│   └── audit-exporter/
├── agents/
│   ├── supervisor/
│   ├── cloud-manager/
│   ├── kubernetes-manager/
│   ├── virtualization-manager/
│   ├── network-manager/
│   ├── identity-manager/
│   ├── pam-manager/
│   ├── compliance-manager/
│   ├── cost-manager/
│   ├── incident-manager/
│   └── evidence-manager/
├── connectors/
│   ├── identity/
│   │   ├── oidc/
│   │   ├── saml/
│   │   ├── scim/
│   │   ├── ldap/
│   │   ├── radius/
│   │   ├── keycloak/
│   │   ├── entra/
│   │   ├── okta/
│   │   └── google-workspace/
│   ├── pam/
│   │   ├── cyberark/
│   │   ├── beyondtrust/
│   │   ├── delinea/
│   │   └── generic-pam/
│   ├── clouds/
│   │   ├── aws/
│   │   ├── azure/
│   │   ├── gcp/
│   │   ├── alibaba/
│   │   └── huawei/
│   ├── virtualization/
│   │   ├── proxmox/
│   │   ├── vmware/
│   │   ├── virtualbox/
│   │   ├── kvm/
│   │   └── cloudstack/
│   ├── containers/
│   │   ├── kubernetes/
│   │   ├── openshift/
│   │   └── registry/
│   ├── security/
│   │   ├── splunk/
│   │   ├── elastic/
│   │   ├── wazuh/
│   │   ├── sentinel/
│   │   └── generic-siem/
│   ├── physical/
│   │   ├── badge-access/
│   │   ├── vms-events/
│   │   ├── hikvision-events/
│   │   ├── zero-tech-events/
│   │   └── generic-camera-metadata/
│   └── business/
│       ├── service-now/
│       ├── jira/
│       ├── sap/
│       └── n8n/
├── policies/
│   ├── base/
│   ├── identity/
│   ├── privileged-access/
│   ├── break-glass/
│   ├── contractors/
│   ├── service-accounts/
│   ├── ai-agents/
│   ├── kubernetes/
│   ├── openshift/
│   ├── cloud/
│   ├── virtualization/
│   ├── network/
│   ├── data-protection/
│   ├── change-management/
│   ├── finops/
│   └── skill-supply-chain/
├── execution/
│   ├── runner-images/
│   ├── terraform-runner/
│   ├── kubernetes-runner/
│   ├── ssh-runner/
│   ├── rdp-runner/
│   ├── cloud-cli-runner/
│   └── sandbox-runner/
├── ui/
│   ├── operator-console/
│   ├── approval-console/
│   ├── graph-console/
│   ├── evidence-explorer/
│   ├── compliance-console/
│   ├── cost-console/
│   └── board-console/
├── deploy/
│   ├── docker/
│   ├── compose/
│   ├── helm/
│   ├── openshift/
│   ├── air-gapped/
│   ├── private-cloud/
│   └── disaster-recovery/
├── tests/
│   ├── unit/
│   ├── contract/
│   ├── conformance/
│   ├── policy/
│   ├── adversarial/
│   ├── chaos/
│   ├── replay/
│   └── benchmark/
└── commercial/
    ├── enterprise-control-plane/
    ├── assurance-engine/
    ├── managed-service/
    ├── premium-connectors/
    ├── agent-governance/
    ├── deployment-operator/
    ├── support-portal/
    └── board-risk-console/
```

## 6. Identity model

The system recognizes:

- Human identities
- Organizations and tenants
- Teams and roles
- Service accounts
- Workload identities
- AI-agent identities
- Tool identities
- Devices and authenticators
- Assets and resources
- System integrators and external operators

Every authorization request has a subject, action, target, purpose, context, requested duration, evidence references, and risk classification.

Example:

```json
{
  "subject": "spiffe://a2z.local/agent/cluster-remediator",
  "human_sponsor": "user:operator-42",
  "action": "kubernetes.patch",
  "target": "cluster:prod-egypt-01/deployment/api",
  "purpose": "remediate-image-vulnerability",
  "requested_duration_seconds": 600,
  "risk": "HIGH",
  "evidence": ["finding:VULN-123", "plan:sha256:..."],
  "approval_required": true
}
```

## 7. Authorization model

Combine three models:

1. **Relationship authorization:** subject-to-tenant, team-to-project, operator-to-environment, and system-integrator relationships.
2. **Policy-as-code:** action, target, risk, time, location, device posture, change window, and evidence conditions.
3. **Capability tokens:** short-lived, narrow credentials minted only after policy approval.

The decision engine returns:

```json
{
  "decision": "allow|deny|needs_approval|needs_step_up",
  "reasons": [],
  "required_approvers": [],
  "maximum_duration_seconds": 600,
  "permitted_tools": [],
  "permitted_targets": [],
  "evidence_requirements": []
}
```

## 8. Agent hierarchy

### Supervisor agent

Translates spoken or written intent into typed requests. It cannot directly mutate infrastructure.

### Domain agents

Each domain agent owns discovery, diagnosis, planning, and verification for one domain. It cannot use another domain's credentials.

### Execution agents

They receive one approved plan and one short-lived capability. They return structured results and evidence.

### Evaluator agents

They assess plan quality, policy compliance, risk, cost, and outcome. They do not approve their own changes.

## 9. Voice and smart-glasses interaction

The smart glasses are an audio endpoint. Codex Voice runs on the macOS desktop app. Android can act as a backup control and approval surface. Voice commands are transcribed, shown as text, and converted into typed intent. A voice command cannot by itself authorize a high-risk action.

### Command classes

- Read: inspect, list, explain, compare.
- Plan: produce a diff, cost estimate, impact analysis, and rollback.
- Approve: explicitly approve a previously displayed plan.
- Execute: only after a second factor and policy gate.
- Stop: revoke current capabilities and cancel pending execution.

### Voice confirmation format

Before a high-risk action, Codex must state:

```text
Target: <exact target>
Action: <exact mutation>
Impact: <blast radius>
Estimated cost: <estimate>
Rollback: <method>
Approval: say “approve <short code>” and confirm with passkey
```

## 10. Infrastructure domains

### 10.1 Ubuntu operations host

Run the control plane, policy services, runners, telemetry, and local lab. Use separate service accounts, systemd hardening, disk encryption, automatic security updates where compatible, and an isolated execution network.

### 10.2 Proxmox/KVM

Use the API for inventory, VM lifecycle, storage, snapshots, networks, and cluster health. Destructive actions require a plan, snapshot or backup check, and explicit approval.

### 10.3 VMware

Use vCenter APIs and Terraform provider workflows. Avoid direct host mutation when vCenter is the source of truth.

### 10.4 VirtualBox

Use for small local compatibility tests, not as the primary production-like virtualization layer.

### 10.5 CloudStack

Use API-driven zone, pod, cluster, network, template, account, and VM management. Model CloudStack resources in the inventory graph with provider-specific capabilities.

### 10.6 Kubernetes/OpenShift

Use API clients, admission policies, RBAC, namespace boundaries, resource quotas, network policies, image-signing checks, and GitOps where practical. Never let a general agent receive unrestricted cluster-admin.

### 10.7 Public clouds

Create separate accounts/subscriptions/projects for lab, staging, and production. Use cloud-native federation and short-lived roles. Maintain a provider-neutral capability model, but keep provider-specific policy adapters.

## 11. Terraform/OpenTofu workflow

```text
discover
  -> normalize inventory
  -> generate or update IaC
  -> fmt/validate
  -> security and policy checks
  -> plan artifact
  -> cost and blast-radius analysis
  -> approval
  -> isolated apply runner
  -> post-apply verification
  -> evidence and state reconciliation
```

Never apply from an unreviewed working tree. Never destroy without a destroy plan, explicit approval, backup verification, and a recovery path.

## 12. Compliance-as-code

Policies should be versioned, tested, explainable, and mapped to controls. Start with:

- Least privilege
- MFA and phishing-resistant authentication
- JIT privilege and expiry
- No shared administrator accounts
- Encryption and key rotation
- Network segmentation
- Backup and recovery
- Logging and retention
- Vulnerability management
- Change approval
- Agent tool restrictions
- Data minimization
- Tenant isolation
- Secrets not present in logs or source

Every control produces evidence, status, owner, severity, remediation, and last verified time.

## 13. Evidence graph

The core data model links:

```text
identity -> request -> policy decision -> approval -> credential -> tool call
         -> target -> change -> verification -> outcome -> incident/audit
```

The graph must support point-in-time replay. Evidence records are append-only, signed, tenant-scoped, and exportable. Raw video and biometric data are not required for the base product; event metadata is preferred.

## 14. Commercial boundary

### Open source

- Provider adapters
- Event and authorization schemas
- SDKs
- Basic policy examples
- Local deployment
- Connector test harness
- Basic audit export
- Reference Terraform/OpenTofu modules
- Community integrations

### Commercial

- Multi-tenant enterprise control plane
- Advanced policy compiler and assurance engine
- Evidence graph and replay
- Agent identity and tool governance
- Privileged-session controls
- Premium and certified connectors
- Sovereign and air-gapped deployment operator
- Managed control service
- Continuous compliance and board reporting
- Integrator fleet console
- Support, SLAs, training, and incident response

### Ownership structure

An IP HoldCo owns core code, trademarks, schemas, policy engine, models, and commercial licenses. Operating companies sell and deliver services. Customer data remains tenant-specific. Integrators receive implementation and service revenue without ownership of the core control plane.

## 15. Initial packages

### Open Core

Free self-hosted integration fabric for developers, labs, and small teams.

### Privileged Action Assurance

JIT access, approvals, expiry, command/session evidence, and audit replay.

### Agent Authority

Identity, tool permissions, action policy, approvals, and evidence for AI agents.

### Sovereign Control Plane

Private-cloud, air-gapped, Arabic/English, offline, and regional deployment.

### Managed Control Service

A2Z-operated monitoring, policy maintenance, emergency response, and audit preparation.

Planning price hypotheses, to validate with buyers:

- Diagnostic: $10k–$25k equivalent
- Pilot: $25k–$75k setup plus $5k–$15k/month
- Enterprise: $30k–$100k annual platform license
- Privileged assurance: $5k–$20k/month
- Agent authority: $5k–$25k/month
- Sovereign deployment: $75k–$300k implementation plus support
- Managed service: $10k–$75k/month

Price by governed identities, privileged workflows, agents, evidence volume, and operational responsibility—not camera count.

## 16. Implementation phases

### Phase 0 — Safety foundation

- Create repository and CODEOWNERS.
- Install SkillSpector in an isolated environment.
- Enforce skill-scan CI.
- Create approval ledger.
- Define trust zones and secrets policy.
- Establish an unprivileged lab.

### Phase 1 — Local vertical slice

1. Enroll the Ubuntu/VirtualBox lab read-only from macOS using pinned SSH;
   confirm the operator account, VM UUIDs, and a manually recorded baseline.
2. Demonstrate fresh inventory, exact baseline drift, tenant-scoped evidence,
   and evidence-chain verification. No VM state changes in this first gate.
3. Install the Ubuntu goal/task journal behind its separate pinned-SSH
   forced-command MCP bridge; prove goals and typed plans persist across
   reconnects without implying that they execute.
4. Add one read-only adapter at a time for KVM/Proxmox, VMware, then
   CloudStack. Each must have its own explicit enrollment, credential scope,
   inventory contract, baseline/drift tests, and evidence source.
5. Add Kubernetes/OpenShift observation and Terraform/OpenTofu plan-only
   evaluation; integrate OPA/Rego policy decisions and attach outputs to the
   same task/evidence lineage.
6. Treat each adapter as a distinct capability and trust boundary; a shared
   dashboard or agent never implies shared credentials or cross-platform
   authority.

### Phase 2 — Controlled mutation

- Complete signed approval verification, durable leases, target-state preconditions, kill switches, and regional isolated runner before any mutation path is connected.
- Deploy a root-controlled, independently authenticated runner service with
  worker-side grant, expiry, replay, lease-fencing, kill-switch, and circuit-
  breaker enforcement; the macOS agent must not possess provider credentials.
- The source now includes a systemd-activated, local Unix-socket grant signer
  running as a dedicated non-root identity. It pins the initial scope to one
  tenant, runner, target, operation, and short runtime; the API account cannot
  read the key. This protects the key but intentionally trusts the API to
  validate authorization, so API compromise can still request a grant within
  that narrow scope. Staged signer and worker API installers exist but have
  not been run, and neither service is Linux-validated. Do not run the API as
  root or weaken key permissions; install only after peer-UID,
  socket-permission, key-isolation, rotation/revocation, and one-shot permit
  tests pass on the authorized Ubuntu host.
- Add a JIT credential broker that issues a capability only for the exact
  target, operation, environment, task, and short execution window.
- Canary on one disposable lab VM or namespace, then verify both desired state
  and safety invariants from an independent observer; prove rollback and
  idempotent recovery before expanding the canary.
- Make the first VirtualBox mutation canary metadata-only and code-fixed:
  change one powered-off lab VM's description from the exact observed
  `A2Z-Control-Plane-Unlabeled` value to `A2Z-Control-Plane-Demo`, with exact
  rollback. A unit-tested, single-operation adapter boundary now enforces that
  plan and requires fresh signed-grant preflight, worker kill-switch checks, and
  a one-shot permit-consumer interface. The authenticated lease source, permit
  consumer and signed receipt path now exist in source through the mTLS worker
  API, but there is no installed worker/API service, runner identity deployment,
  or Linux-validated path. The journal-side durable breaker is implemented;
  local runner-side breaker enforcement and deployment wiring remain open. Do not
  promote VM start/shutdown to routine autonomy; they remain individually
  approval-gated high-impact actions.
- Require individual human approval for production, destructive, security-
  boundary, regulated, high-blast-radius, uncertain, or out-of-policy actions.
- Enable unattended routine actions only within a signed, expiring owner
  envelope with explicit targets/exclusions, operations, windows, budget,
  concurrency/batch/canary limits, health thresholds, retry/rollback bounds,
  notifications, and emergency-stop behavior.

### Phase 3 — IAM/PAM and agents

- Implement per-human, per-agent, per-runner, per-verifier, and per-GUI-session
  identities; bind short-lived JIT grants to exact task, plan, target, and
  operation. Delegated agents can only narrow scope.
- Integrate Keycloak/Entra/OIDC and workload identity; add PAM session
  brokering, just-in-time elevation, session evidence, revocation, and a
  separately governed human break-glass workflow.
- Treat Hermes as an optional proposal/orchestration runtime behind the
  existing policy and tool gateways. Use signed runtime profiles, bounded
  delegation/fan-out, allowlisted MCP tools, and pinned skill digests. Hermes
  command approvals do not replace control-plane authorization.
- Add an OpenRouter-like model gateway with classification-aware provider,
  model, region, retention, and spend policies. Restrict fallbacks to approved
  routes of equal-or-stronger protection; inference retries must never replay
  infrastructure side effects. The gateway has no infrastructure credentials.
- Add Computer Use only as a separate isolated ephemeral desktop adapter;
  read-only first, allowlisted applications/actions, human confirmation for
  consequential actions, cancellation and budgets, with independent API-based
  postcondition verification.
- Design and test these integrations in simulation before installing Hermes,
  adding skills, connecting a provider, or opening a live GUI session. See
  [`docs/HERMES_SWARM_GOVERNANCE.md`](./docs/HERMES_SWARM_GOVERNANCE.md).

### Phase 4 — Clouds

- AWS, Azure, and GCP first.
- Start with read-only organization/account/project inventory and policy
  mapping; explicitly enroll each account/subscription/project and region.
- Add cost and blast-radius estimates, provider-specific least-privilege
  workload identity, and evidence normalization before any write adapter.
- Prove one isolated non-production change per provider under the same
  plan/approval/canary/verification contract; never reuse provider credentials.

### Phase 5 — Regional providers

- Alibaba and Huawei adapters.
- Regional hosting.
- Arabic reports.
- Data boundary controls.

### Phase 6 — Fleet scale and resilience gate

- Run scale tests against at least 10,000 synthetic assets across multiple
  tenants, regions, virtualization types, clusters, and cloud accounts before
  describing the system as a thousands-device control plane.
- Partition inventory, evidence, queues, and execution capacity by tenant and
  region; enforce per-tenant quotas, back-pressure, fair scheduling, and
  bounded fan-out. Codex/macOS submits goals but is not the always-on fleet
  controller or an SSH loop over every device.
- Exercise controller restart, duplicated/out-of-order events, stale inventory,
  partial regional outage, identity-provider outage, runner compromise,
  credential-broker outage, and emergency stop. Verify no cross-tenant work,
  unbounded retries, or stale-plan execution.
- Require signed connector manifests, compatibility/security gates, adapter
  conformance tests, immutable release provenance, and a staged rollout per
  region/provider version.

### Phase 7 — Demonstration system

- Smart-glasses audio path.
- Codex Voice on Mac.
- Operator and board dashboards.
- Hyperframes/Remotion narrated demonstration.
- Real screenshots from the authenticated control plane.

## 17. Evaluation benchmarks

| Dimension | Target |
|---|---|
| Inventory accuracy | 95%+ for declared environments |
| Unauthorized mutations | 0 |
| Persistent broad credentials | 0 for agent runners |
| Plan reproducibility | Same input produces equivalent plan |
| Rollback | Tested for every destructive class |
| Evidence completeness | 100% of privileged actions linked to identity and approval |
| Policy latency | Defined p95 per decision tier |
| Drift detection | Within agreed polling/event window |
| Cost forecast error | Tracked by provider and environment |
| Agent tool violations | 0 successful violations |
| Skill supply-chain gate | 100% of installed skills have pinned approvals |
| Recovery | RTO/RPO documented and tested |

## 18. First demonstration script

1. Operator says: “Run a read-only inventory of all local and cloud environments.”
2. Supervisor confirms scope and creates a signed observation request.
3. Domain agents collect inventory through provider APIs.
4. Graph console displays identity, asset, privilege, and dependency relationships.
5. Compliance agent identifies a public endpoint and standing admin role.
6. Operator asks for remediation plans, not execution.
7. Terraform/OpenTofu plan and cost/blast-radius estimate appear.
8. Policy engine marks the plan high risk and requires second approval.
9. Operator confirms on the Mac and passkey device.
10. Runner receives a 10-minute capability token.
11. Runner applies the approved plan.
12. Verification agent checks health, policy, and drift.
13. Evidence ledger stores the full chain.
14. Voice agent narrates the before/after result.
15. Board console shows risk reduction, cost impact, and remaining exceptions.

## 19. Fresh-agent instructions

The new Codex agent must read `AGENT_BOOTSTRAP.md`, then `SKILL_INGESTION_SECURITY.md`, then `THREAT_MODEL.md`, before changing code or installing skills. It must not install a skill directly from skills.sh or GitHub. It must use the gated wrapper, store the scan report, and ask for a review only when the policy marks the skill conditional or blocked. It must begin with read-only discovery and produce a plan before mutation.
