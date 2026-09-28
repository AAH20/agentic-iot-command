# Journal-side postcondition API deployment

This is an optional, separate service for the Ubuntu 26.04 lab. The existing
account must use its dedicated a2z-control primary group; the installer
refuses a different primary group. It only serves
postcondition candidate and signed-attestation routes. It does not run
VirtualBox commands, claim runner leases, issue execution grants, or mutate
infrastructure. It runs under the existing a2z-control journal account and
binds to 127.0.0.1:9444; the future VM observer must use a distinct account.
Do not add a2z-control to vboxusers or any VM-access group.

Do these steps only after host identity and base goal-gateway onboarding in
docs/GOAL_MCP_SETUP.md, and only on a host you are authorized to administer.

## Install files, stopped

Transfer a reviewed, versioned package over a trusted private path and verify
its release checksum before running its installer. On Ubuntu:

    sudo bash scripts/install-postcondition-api-linux.sh

The installer refuses existing destinations. It copies a separate, root-owned
code tree to /opt/a2z-postcondition-api, creates empty root-managed TLS and
public-key trust directories, and installs a hardened systemd unit. It does
not create keys, write the active configuration, reload systemd, start or
enable the service, alter SSH/firewall settings, or grant VM permissions.

## Configure reviewed trust

1. Use the reviewed config sample at
   /opt/a2z-postcondition-api/config/postcondition-api.example.json to create
   /etc/a2z-control-plane/postcondition-api.json, root-owned, readable by the
   a2z-control primary group, mode 0640. Keep the bind address at 127.0.0.1
   and port at 9444. Confirm the database path is the same owner-only goal
   journal used by the SSH gateway.
2. Provision the API server certificate and client CA through the lab's
   approved certificate process. The server certificate must contain the
   IP:127.0.0.1 subject alternative name and serverAuth usage. Use the
   installer-created `/etc/a2z-control-plane/postcondition-tls/` directory.
   Put `postcondition-api.key` there, owned by a2z-control, mode 0600; keep
   its parent directory root-owned and not group/other writable. The server
   certificate and client-CA certificate must be root-owned and not
   group/other writable.
3. Create the verifier registry from
   /opt/a2z-postcondition-api/config/postcondition-verifiers.example.json.
   Replace the all-zero certificate fingerprint with the SHA-256 fingerprint
   of the separately provisioned verifier client certificate, and replace the
   target placeholder with the one reviewed VirtualBox UUID. Keep one exact
   tenant, verifier ID, operation, and lab environment. Install as
   /etc/a2z-control-plane/postcondition-verifiers.json, root-owned,
   group-readable by the a2z-control primary group, mode 0640. Do not put a private key in this
   registry.
4. Place only the observer's Ed25519 public key in
   /etc/a2z-control-plane/postcondition-attestation-trust/<key_id>.pem,
   owned by root, readable by the a2z-control primary group, and not
   group/other writable.
   Keep the private key only with the future observer service identity. Keep
   the CA that issued observer client certificates separate from this signing
   key trust directory; these authenticate different things.
5. Confirm the service account has no VirtualBox access, the observer identity
   is not the runner identity, and the active mutation switch remains disabled.

Example ownership for active, non-secret files:

    sudo chown root:a2z-control /etc/a2z-control-plane/postcondition-api.json
    sudo chmod 0640 /etc/a2z-control-plane/postcondition-api.json
    sudo chown root:a2z-control /etc/a2z-control-plane/postcondition-verifiers.json
    sudo chmod 0640 /etc/a2z-control-plane/postcondition-verifiers.json
    sudo chown root:a2z-control /etc/a2z-control-plane/postcondition-attestation-trust/<key_id>.pem
    sudo chmod 0640 /etc/a2z-control-plane/postcondition-attestation-trust/<key_id>.pem

Replace <key_id> with the exact reviewed signing-key identifier. Never paste
private keys into a shell command or this configuration.

## Validate before enabling

Run the unit verifier and inspect the ownership of every installed file:

    sudo -u a2z-control /usr/bin/python3 /opt/a2z-postcondition-api/scripts/postcondition-api-server.py --check-config
    sudo systemd-analyze verify /etc/systemd/system/a2z-postcondition-api.service
    sudo systemctl daemon-reload
    sudo systemctl start a2z-postcondition-api.service
    sudo systemctl --no-pager --full status a2z-postcondition-api.service
    sudo ss -ltnp

Confirm the only listener is 127.0.0.1:9444 and the service process is
a2z-control. The unit denies non-loopback IP traffic and the application
refuses non-loopback binds. Then perform an mTLS handshake using the separately
issued observer certificate and pinned CA. Do not enable the unit at boot or
start the observer until Linux-side handshake, candidate-scope, signature,
idempotent-replay, and journal-evidence checks pass. Stop the service if it
binds another address, accepts an untrusted client, or exposes any extra route.

This API service alone is not a usable verifier deployment: the separate
read-only VirtualBox observer service, durable local outbox path, Linux
end-to-end test, and operational recovery procedure still need deployment and
review. No task should be treated as live-verified until those gates pass.
