# Independent postcondition verification

Runner receipts are signed execution claims. They are not proof that the target
resource reached its desired state. For the first VirtualBox lab action, the
separate postcondition contract is:

1. `DurableGoalStore.get_postcondition_candidate` returns only a task in
   `verification` with its server-stored plan and previously signature-verified
   runner receipt.
2. `IndependentVirtualBoxPostconditionObserver` validates the task, plan
   digest, lease generation, receipt identity, fixed operation, and UUID target.
   Its only target command is fixed read-only
   `VBoxManage showvminfo <UUID> --machinereadable`.
3. The observer signs the actual typed observation with the
   `a2z.postcondition-attestation.v1` domain. The verifier uses a separate
   public-key trust directory and an explicit allowlist of verifier identities;
   runner keys cannot satisfy this trust check.
4. `DurableGoalStore.record_postcondition_attestation` rechecks the stored plan
   and runner receipt, derives the exact expected state from the code-owned
   operation contract, and compares it with the signed observation. Exact match
   records `task.completed`; mismatch records `task.postcondition_mismatch_blocked`,
   blocks the task, and opens the target/operation circuit breaker. Neither
   outcome enables further execution.

The signed observation is strict: one verification ID, one runner receipt ID,
exact task/tenant/target/operation/environment/plan/generation scope, verifier
identity, fresh timestamp, and only `power_state` and `description`. The journal
does not trust a signed `verified: true` field; it computes equality itself.

## Deployment boundary

This is source-level verification logic, not a deployed independent observer.
The observer must run under a distinct Linux service UID from the mutation
runner, with a distinct Ed25519 private key and root-managed public-key trust
directory. It needs only read-only VirtualBox observation and an authenticated,
read-only way to fetch verification candidates plus a narrow way to submit its
signed result. `control_plane_core.postcondition_api` now provides that narrow
source-level mTLS transport, with a verifier-specific certificate registry
and exact tenant/target/operation/environment scope. Its routes are
`GET /v1/postconditions/ready` for bounded metadata polling,
`GET /v1/postconditions/{task_uuid}` for one candidate, and
`POST /v1/postconditions/{task_uuid}/attestation` for signed-result submission;
the tenant and verifier IDs come from the authenticated certificate mapping,
not request fields. The
companion client pins the server CA, requires TLS 1.2+, disables proxies and
redirects, and rejects out-of-scope responses. The API cannot claim runner
leases, issue grants, or execute commands.

Do not share the runner private key, worker UID, arbitrary shell, or VM
mutation permissions with the observer. The package now includes a strict
root-owned verifier identity-registry loader and a JSON schema/example, but the
loader is not yet wired into a service entrypoint or installer. The observer
service unit and Linux end-to-end test remain deployment work. Until those are
reviewed and completed, no task should be treated as independently verified in
a live installation.

`PostconditionAttestationOutbox` stores the signed envelope in an owner-only
SQLite file before submission. If a response is lost, `run_once` replays the
exact envelope before polling new candidates; it does not repeat observation or
mint a conflicting verification ID. A pending record remains durable on
transport failure.

The JSON contract is in
[`schemas/postcondition-attestation.schema.json`](../schemas/postcondition-attestation.schema.json).
The registry contract and loader are in
[`schemas/postcondition-verifier-registry.schema.json`](../schemas/postcondition-verifier-registry.schema.json)
and [`src/control_plane_core/postcondition_registry.py`](../src/control_plane_core/postcondition_registry.py).
