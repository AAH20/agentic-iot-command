# Runner and Credential Boundaries

Capability authorization, grant issuance, runner execution, and independent
verification are separate trust boundaries. The local reference simulation
still denies real credential issuance and runs with network/credentials off;
that simulation is not evidence that the Ubuntu worker is deployed.

The source tree now also contains a first, narrowly scoped live-path contract:

- `AuthenticatedWorkerAPI` and `MTLSWorkerClient` define certificate-scoped
  lease, grant, one-shot-consumption, runner-receipt, and late-receipt routes.
  The journal derives tenant/runner scope from the mTLS certificate and
  requires the runner receipt key ID to match that authenticated runner.
- `GovernedVirtualBoxWorker` persists signed receipts before delivery and
  never retries the infrastructure action to recover a lost response.
- `VirtualBoxDemoAdapter` supports one fixed powered-off VM metadata change;
  it has no shell or arbitrary argument path and requires fresh grant
  preflight, a kill switch, and one-shot journal consumption.
- Independent postcondition observation has its own signing key, durable
  outbox, mTLS identity, and journal-verification route. A runner receipt by
  itself cannot complete a task.

These are tested source components, not an installed or Linux-validated worker.
The worker API now has a source entrypoint, strict mTLS identity-registry
loader, root-managed config validation, loopback-only systemd unit, and staged
Ubuntu installer. None is installed or Linux-validated. There is still no
isolated executor service or Ubuntu mTLS/VirtualBox exercise. Do not start the
listener until reviewed certificates and configuration are installed and the
host-specific controls below pass.

## Deployment gate: signing key and VM authority

The direct `Ed25519ExecutionGrantSigner` requires a protected private key that
the unprivileged journal/API account cannot read. A separate source-level
`UnixExecutionGrantSigner` client and systemd-activated signer service now keep
the key in a dedicated non-root identity and pin signing to one tenant, runner,
target, operation, and short runtime. This boundary protects key material but
trusts the API process to validate signed approval or standing-policy evidence;
it does not independently prove the authorization. A staged signer installer
exists but has not been run; the worker API installer also exists but has not
been run, and neither service is Linux-validated. Do not run the API as root or loosen key
permissions. Before service deployment, review this trust assumption and test
peer-UID rejection, key isolation, revocation, and rotation on Ubuntu.

The executor's effective VirtualBox permissions are host-specific. Do not add
it to `vboxusers`, grant broad VM-directory access, or enable the mutation
switch before inventorying the actual VM owner, storage paths, device
permissions, and a disposable canary. The eventual executor must be a separate
unprivileged identity, constrained to the selected demo VM and hardened by an
OS sandbox; the journal, observer, and Codex identities must not gain VM
mutation access. Prove the boundary on Ubuntu before observer or executor
installation.

## Runner-side preflight status

`control_plane_core.runner_preflight.RunnerPreflight` now implements a
non-executing worker-side check: it obtains the current lease from an injected
authenticated lease source, binds the request to the runner identity, checks
that the lease is live and in the execution stage, recomputes the canonical
plan digest, rejects operations outside the code-owned catalog, applies the
operation-specific typed-plan validator, and verifies the signed grant against
claims derived from that lease (including the lease-token digest and fencing
generation). It also checks that grant expiry and runtime fit within the lease
and plan. The lease token is not returned in the preflight result.

The `RunnerPreflight`, mTLS worker client/API, adapter, receipt outbox, and
independent observer now connect these interfaces at source level. They remain
non-deployable until the signer and worker service packaging, runner identity
configuration, root-managed controls, service supervision, Linux mTLS tests,
and host-specific VirtualBox isolation are completed. The journal transition
is not permission to call an arbitrary infrastructure API, and
`execution_permitted` remains false in evidence/receipts. Never connect this
primitive to a shell, generic SSH command, Terraform, Kubernetes, or cloud API;
each future adapter needs its own typed allowlist and independent gates.
