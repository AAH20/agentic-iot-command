# Confined execution-grant signer

The API process must not be able to read the Ed25519 grant-signing private
key. `control_plane_core.grant_signer_service` provides a local-only signer
boundary: a systemd-activated Unix socket accepts requests only from one
configured API UID, and a dedicated non-root signer identity owns the key.
The signer pins exactly one tenant, runner, target, and operation for the
initial VirtualBox canary, and rejects production scopes, unsupported grant
claims, expired grants, and runtimes above its configured ceiling. The normal
runner verifier still validates the complete signature and lease claims.

This boundary protects private-key confidentiality and limits the signing
scope; it is not an independent policy decision point. The API UID is trusted
to validate the signed operator approval or standing-policy profile and impact
assessment before requesting a signature. Compromise of that API can still
request a grant within the signer's pinned one-target/one-operation/runner
scope. The journal's one-shot permit consumption, root-managed execution
switch, and runner preflight remain mandatory. Do not widen the policy to
additional targets, operations, tenants, or environments until an independent
signer-side authorization validator and key rotation/revocation tests exist.

## Service contract

- Unix socket only; no TCP listener or remote signing API.
- Linux `SO_PEERCRED` UID check on every request. Unsupported peer-credential
  platforms fail closed.
- Bounded, duplicate-key-rejecting JSON request and response.
- systemd socket activation; the service refuses direct or unexpected FDs.
- API client pins both the signer UID and expected signing `key_id`; the runner
  cryptographically verifies the returned envelope against its trust store.
- Signer runs non-root, has no network address family, and reads a service-owned
  owner-only key. The API account can connect to the socket but cannot traverse
  the key directory.
- Keep signer config and key material under the separate
  `/etc/a2z-grant-signer/` tree (config root:`a2z-grant-signer` 0640, directory
  0750; key signer:`a2z-grant-signer` 0400, key directory root:`a2z-grant-signer`
  0710). Do not add the signer identity to the `a2z-control` group or give it
  journal/database access.
- The example config and schema are templates only. The all-zero VM ID is not
  an enrolled target and must be replaced only after read-only Linux inventory
  and explicit operator selection of a disposable VM.

The staged installer is `scripts/install-grant-signer-linux.sh`. It targets
Ubuntu 26.04, refuses pre-existing identities/paths, copies reviewed code and
unit files, and creates the dedicated identity and empty protected directories.
It does not create active configuration or keys, run `daemon-reload`, start or
enable units, or touch SSH, firewall, VirtualBox membership, or the execution
switch. It has not been run on Ubuntu. After reviewing its source and verifying
the transferred package checksum, install stopped files with:

    sudo bash scripts/install-grant-signer-linux.sh

Do not start the socket yet: the worker API service, signer client, and staged
installer exist only in source and are not installed; the exact VM UUID, runner
identity, API UID, and trust-store configuration must be selected and reviewed
on the host. Before activation,
validate socket activation, peer UID rejection, private-key isolation, grant
signature verification, signer restart behavior, and key rotation on Ubuntu.
Keep the execution switch disabled throughout.
