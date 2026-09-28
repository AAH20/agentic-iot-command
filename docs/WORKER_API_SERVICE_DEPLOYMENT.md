# Ubuntu worker API service deployment

This is the journal-side runner API for the fixed VirtualBox demo worker. It
does not run `VBoxManage`, accept shell commands, or own runner credentials. It
binds only to `127.0.0.1:9443`, requires mTLS, derives runner scope from the
client certificate registry, and delegates grant signing to the separate
`a2z-grant-signer` identity. The execution-control file must remain disabled
through installation and validation.

This service is separate from the macOS Codex SSH goal gateway and the
postcondition verifier API. Install only on a host you own or are authorized to
administer, after the base goal gateway and staged grant-signer package exist.

## Install stopped files

Transfer a reviewed package over a trusted private path and verify its release
checksum. On the Ubuntu 26.04 host:

    sudo bash scripts/install-worker-api-linux.sh

The installer refuses existing destinations. It copies a root-owned source
tree, verifier scripts, example configs, and a hardened systemd unit; creates
an empty autonomy-policy trust directory and a TLS directory; and leaves the
service stopped/disabled. It does not create active configuration, certificates,
private keys, trust keys, or runner certificates; it does not reload systemd,
change SSH/firewall, add VM groups, or enable mutation. If any destination
already exists, stop and review it rather than overwriting it.

## Configure reviewed identity and trust

Do not use the example UUID, fingerprint, signer UID, or signing key ID as
live values. Select the exact disposable lab VM only after read-only inventory.

1. Copy `config/worker-api.example.json` to
   `/etc/a2z-control-plane/worker-api.json` with owner `root:a2z-control`,
   mode `0640`. Replace `signer_uid` with `id -u a2z-grant-signer`; set the
   `signer_key_id` to the reviewed issuer key ID. Keep bind address and port at
   `127.0.0.1:9443`; do not expose the API on a LAN or the Internet.
2. Copy `config/worker-identities.example.json` to
   `/etc/a2z-control-plane/runner-identities.json`, also root:`a2z-control`
   mode `0640`. Replace the placeholder target with the selected VM UUID and
   fingerprint with the SHA-256 digest of the exact runner client certificate
   in DER form. Keep one lab runner, one exact VM, and the single
   `virtualbox.vm.set_demo_description` operation for this first canary. The
   certificate URI SAN, tenant, runner ID, and API registry must agree.
3. Provision the worker API server certificate, its owner-only private key,
   and a runner client CA from the lab's approved certificate process. The
   server certificate needs an IP SAN for `127.0.0.1` and server-auth usage;
   the runner certificate needs client-auth usage and the exact SPIFFE URI SAN
   above. Put files in `/etc/a2z-control-plane/worker-tls/`; the private key
   must be `a2z-control`-owned mode `0600`, and public certificate/CA files
   root-owned and not group/other writable. The worker client private key
   belongs only on the isolated runner, not in this server directory.
4. Install public keys only (never private keys) into the already-created,
   root-managed trust directories:
   - operator approval key: `approval-trust/<approval-key-id>.pem`;
   - runner receipt key: `runner-trust/<runner-id>.pem`;
   - signer public key: `execution-grant-trust/<signer-key-id>.pem`.

   Keep files root-owned and not group/other writable. Keep certificate-CA
   trust separate from Ed25519 signing-key trust. The autonomy and impact
   trust directories may remain empty for operator-approved lab tasks; in that
   state standing-policy execution cannot authorize work. Do not create fake
   profiles, assessments, or approval keys to make validation pass.
5. Confirm `/etc/a2z-control-plane/execution-control.json` still says
   `execution_enabled: false`. Do not install VirtualBox permissions on the
   API account or add it to `vboxusers`.

## Validate without starting listeners

Run checks only after the real certificates, registry, and public trust keys
are installed:

    sudo -u a2z-control /usr/bin/python3 /opt/a2z-worker-api/scripts/worker-api-server.py --check-config
    sudo systemd-analyze verify /etc/systemd/system/a2z-grant-signer.socket /etc/systemd/system/a2z-grant-signer.service /etc/systemd/system/a2z-worker-api.service

`--check-config` validates trust and the disabled kill switch but does not open
the journal, connect to the signer, or bind a listener. Fix any failure before
continuing. Do not use `curl -k`, wildcard binds, or firewall openings.

The source-level API and signer still require on-host tests for mTLS identity
mapping, untrusted-certificate rejection, strict route allowlisting, Unix
socket peer-UID rejection, signer key isolation, one-shot permit consumption,
receipt recovery, and restart behavior. The runner/executor service and
independent postcondition observer are not installed by these steps. Do not
start the API or signer socket, enable units at boot, enable the kill switch,
or perform a mutation until those separate components and reviews are present.
