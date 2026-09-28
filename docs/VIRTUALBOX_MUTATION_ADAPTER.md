# VirtualBox mutation adapter boundary

## Scope

`control_plane_core.virtualbox_adapter.VirtualBoxDemoAdapter` is the first
mutation adapter for the Linux/VirtualBox demonstration. Its entire supported
mutation catalog is one reversible metadata change:

```text
virtualbox.vm.set_demo_description
VBoxManage modifyvm <one-UUID> --description A2Z-Control-Plane-Demo
```

The adapter does not accept shell text, arbitrary command arguments, VM names,
wildcard targets, start/stop/delete operations, or user-selected descriptions.
It requires the exact lab plan, a valid UUID target, powered-off state, and the
initial demo label. It checks the state before the action, verifies the signed
grant against fresh lease state twice, checks the worker kill switch, asks an
authenticated one-shot permit consumer to atomically consume the exact grant,
and verifies the resulting state. If an attempted mutation has an uncertain or
incorrect postcondition, it tries the code-owned rollback only when the VM is
still powered off and exactly in the adapter's desired state; it reports whether
that rollback was verified.

The child process uses a fixed absolute executable, argument vector (no shell),
bounded timeout, closed file descriptors, and a reduced environment. The worker
must run as a dedicated, unprivileged account that owns only the demonstration
VMs; this adapter must not be run as root or given access to unrelated VM
directories.

## Not yet live

This is a tested operation boundary plus a source-level one-shot coordinator,
not a deployed worker. `MTLSWorkerClient` implements the authenticated
lease-source and one-shot-permit interfaces; `GovernedVirtualBoxWorker`
coordinates ready-queue poll → lease claim → grant issue → fixed adapter →
signed receipt submission for one task. The journal accepts byte-identical
receipt retries idempotently and rejects a conflicting receipt for that lease.
The coordinator requires an owner-only SQLite receipt outbox. It persists the
signed envelope before network submission, retries the exact receipt after a
lost response, and blocks new mutations while receipt delivery is pending. If
the lease expires before submission, the receipt remains local for explicit
reconciliation; no automatic infrastructure retry occurs. Tests use fake
transports/adapters; this sandbox skips the real mTLS listener test because
loopback binding is denied. No VM or host was contacted. Source-level
independent postcondition observation, journal-side verification, and a
verifier-only mTLS API are now implemented in source, but the observer service
is not deployed. Signed, audited late-receipt reconciliation now exists in the
worker API source; still missing are its Linux mTLS validation, the worker
service and runner-identity registry deployment, the independent observer
service, and end-to-end service supervision/installation.
Live autonomous execution is not yet available.

Before any live demonstration, the remaining sequence is:

1. Validate the signed, audited late-receipt reconciliation path on Linux for
   an outbox entry whose lease expires before delivery. It accepts only the
   exact journaled runner/grant/generation and resumes postcondition
   verification; it must never retry the mutation.
2. Deploy the independent postcondition observer under a distinct service
   identity and connect it to the verifier-only mTLS candidate-fetch and
   signed-result routes; ensure only that verifier may move a task from
   `verification` to `completed`.
3. Validate the full mTLS handshake, grant lifecycle, adapter invocation, and
   signed receipt path in an authorized isolated Linux environment.
4. Wire the root-owned identity-registry loader into a reviewed service
   entrypoint, then add service supervision. Install the observer and worker
   under distinct dedicated Linux accounts with root-owned code and trust
   configuration; grant VM-user-only access only to the observer, enforce
   network egress restrictions, and leave the mutation switch disabled by
   default.
5. Begin with read-only observation and simulated permit consumption. Enable the
   one metadata action only after operator review and a canary on a disposable
   lab VM. Leave VM power operations human-approved.

The four adapter tests use an injected command runner and a trusted fixed
executable path solely to validate constructed arguments and policy gates; they
do not invoke VirtualBox. Full unit tests must pass before deployment.
