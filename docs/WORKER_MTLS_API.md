# Runner-to-journal mTLS API

## Contract

`control_plane_core.worker_api` now provides an HTTPS server factory, a
certificate-derived runner identity registry, a scoped worker API, and an mTLS
client implementing the runner lease-source and one-shot-permit interfaces.
The server requires TLS 1.2 or newer and client certificates signed by its
configured workload CA. It then requires exactly one SPIFFE URI SAN and checks
the peer certificate's SHA-256 fingerprint against the enrolled runner record.
Removing or rotating that registry entry revokes the old fingerprint after the
server reload/restart.

The HTTP surface is intentionally small:

| Method and route | Purpose |
| --- | --- |
| `GET /v1/tasks/ready` | Return up to 50 queued task IDs and non-secret metadata inside the certificate-derived runner allowlists; it does not grant a lease. |
| `POST /v1/tasks/{task_uuid}/lease` | Claim the exact task under the certificate-derived tenant/runner; returns the lease token over mTLS. Body must be `{}`. |
| `GET /v1/tasks/{task_uuid}/lease` | Return fresh, runner-scoped lease and plan claims for grant preflight. |
| `POST /v1/tasks/{task_uuid}/grant` | Issue or retrieve the exact signed grant using only the current lease token. |
| `POST /v1/tasks/{task_uuid}/consume` | Atomically consume the one-shot grant using the current lease token and exact grant digest. |
| `POST /v1/tasks/{task_uuid}/attestation` | Submit an Ed25519-signed runner receipt tied to the active fenced lease; records evidence and enters verification, but never marks the task complete. |
| `POST /v1/tasks/{task_uuid}/reconcile-attestation` | Submit the exact signed receipt after lease expiry; reconciliation checks the journaled runner, consumed grant, lease generation, target, plan digest, and grant-bound timestamp window. It can resume verification but cannot queue or execute work. |

The receipt signer uses domain-separated canonical JSON and an owner-only
runner private-key file; the server verifier checks a root-managed public-key
trust directory. The receipt `key_id` must equal the runner ID derived from
the mTLS certificate, binding signing-key trust to the authenticated runner.
The journal opens its target/operation circuit breaker for
failed or unknown outcomes, credential issuance, or any reported network call
under the current zero-network contract. This receipt remains runner-reported
evidence, not independent proof of the resource's postcondition.

There is no shell, arbitrary command, tenant/runner identity field, credential
broker, task discovery endpoint, or production environment. Each enrolled runner
has explicit tenant, target, operation, and environment allowlists. Request
bodies are strict JSON with duplicate-key rejection, a 16 KiB cap, no transfer
encoding, bounded socket timeouts, and no redirects. The API binds loopback by
default; any remote binding must be private, firewall-scoped, and covered by a
dedicated workload CA.

The Mac Codex MCP bridge remains a separate pinned-SSH interface for goals and
policy. Runners authenticate to this API with their own mTLS workload identity;
Codex does not receive runner private keys or lease tokens.

## Independent postcondition verifier API

`control_plane_core.postcondition_api` is a separate mTLS surface, not an
extension of the runner routes. Its verifier-specific certificate registry
maps a pinned certificate fingerprint to one verifier ID, tenant, and exact
target/operation/non-production-environment allowlists. Its only routes are:

| Method and route | Purpose |
| --- | --- |
| `GET /v1/postconditions/ready` | Return a bounded page of candidate metadata inside the verifier's certificate-derived allowlists. |
| `GET /v1/postconditions/{task_uuid}` | Fetch one journal-authorized task in `verification`, including its plan and verified runner receipt. |
| `POST /v1/postconditions/{task_uuid}/attestation` | Submit one Ed25519-signed observation; the journal recomputes expected state and alone decides completion or blocks the task. |

The request cannot supply tenant or verifier identity. The observer certificate
identity is checked before journal access; the signature verifier independently
checks the separate Ed25519 trust domain. The companion client validates the
configured tenant/verifier identity, uses TLS 1.2+, server CA validation,
timeouts, bounded JSON, and rejects redirects. There are no lease, grant,
runner receipt, shell, or mutation routes on this API.

The verifier's `PostconditionAttestationOutbox` persists each signed envelope
before posting. On restart or response loss, the observer replays the exact
envelope; the journal accepts an identical replay idempotently and rejects a
conflicting envelope for the same lease generation.

The source includes a Linux service entrypoint, strict root-managed
identity-registry loader, fail-closed Ubuntu installer, and loopback-only
systemd unit. These are prepared deployment artifacts, not an installed or
Linux-verified service. The HTTPS integration test is skipped when sandbox
policy blocks local listener creation. Install only on the authorized Ubuntu
lab after reviewing the package, and validate the real mTLS handshake there
before use.

## Current deployment status

This is not an installed system. The `GovernedVirtualBoxWorker` source
coordinator handles one supported task per call and uses a runner-local durable
receipt outbox, but there is no deployed long-running worker or independent
postcondition observer. The worker API source includes an audited late-receipt
reconciliation route: a valid old receipt is accepted only for the same
authenticated runner, exact consumed grant, lease generation, target, and
grant-bound timestamp window. A safe success resumes only independent
postcondition verification; failure or out-of-contract evidence keeps the task
blocked and opens the breaker. It never retries the mutation. This route has
unit coverage but no installed worker service or Linux mTLS validation. A separate verifier-only API service entrypoint, installer, and
systemd unit are prepared; they do not install the observer or worker. The
real mTLS handshake is not verified in this sandbox. Staged signer and worker
API service units/installers now define the least-privilege arrangement, but
neither has been installed or validated on Linux, and no executor is deployed.
Keep the execution switch disabled; do not start a worker or run the VirtualBox
mutation adapter on Ubuntu until host-side identity, mTLS, signer, and
independent verification checks pass.

The package includes a real HTTPS/mTLS integration test that creates ephemeral
test certificates, but this sandbox denied loopback listener creation, so that
test was skipped here. Certificate mapping, exact scope enforcement, token and
digest binding, and refusal of optional client authentication are covered by
local unit tests. Re-run the full mTLS handshake test in an authorized isolated
Linux test environment before installation.
