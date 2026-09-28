# Remote access options: SSH and RustDesk

## Roles in the architecture

Use SSH as the machine interface from the Mac control-plane process to the
Linux operations host. The current connector is live but observation-only: it
retrieves a small host summary, the count of failed systemd units, and
registered/running VirtualBox VM inventory. Oracle documents `VBoxManage list
vms` and `VBoxManage list runningvms` for those inventory views ([Oracle
VirtualBox `VBoxManage list`](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/vboxmanage-list.html)).
It does not run arbitrary commands or change the host. RustDesk is a separate,
human-operated desktop session for visual troubleshooting and explicit
operator actions. It is not an agent API and must not be treated as an
approval or audit boundary.

```text
Codex / operator on macOS
  ├── loopback-only observation API ── pinned SSH ── read-only Linux probe
  ├── goal MCP bridge ── pinned SSH forced command ── Ubuntu goal journal
  └── operator launches RustDesk ─────────── Linux desktop (human present)
```

The SSH route is preferred for repeatable inventory and automation. RustDesk
can complement it when a GUI is necessary. Neither route should be exposed
directly to the public Internet. Use a private overlay/VPN or a controlled
bastion. Keep management planes (hypervisors, Kubernetes, cloud consoles) on
their own private control paths; do not tunnel all of them through desktop
control.

## SSH observation setup

1. On the Linux host, create a dedicated non-root account with no general
   `sudo` access. Install the probe from a trusted checkout of this package at
   `/usr/local/libexec/a2z-readonly-probe`, owned by root and not writable by
   the SSH account. For example, from the package root on Linux:

   ```bash
   sudo install -o root -g root -m 0755 scripts/a2z-readonly-probe /usr/local/libexec/a2z-readonly-probe
   ```

   It requires Python 3; systemd health is reported when systemd is available,
   and VirtualBox inventory is reported when `VBoxManage` is available to this
   account. Do not add `sudoers` rules for this probe.
2. On the Mac, create a dedicated SSH key pair for this connector, for example
   `ssh-keygen -t ed25519 -f ~/.ssh/a2z-observe -C a2z-mac-observer`. Keep the
   private key on the Mac in a user-owned directory with mode `0600`; do not
   copy it to Linux, put it in this repository, or enable agent forwarding.
3. Pin the Linux host key into a dedicated `known_hosts` file after verifying
   its fingerprint through a trusted channel. Do not use
   `StrictHostKeyChecking=no` or accept an unverified first-use key.
4. Restrict the public key in the Linux account's `authorized_keys` with a
   forced command and no forwarding or PTY. For example, append the actual
   key material after this option prefix:

   ```text
   restrict,command="/usr/local/libexec/a2z-readonly-probe --stdio" ssh-ed25519 AAAA... a2z-mac-observer
   ```

   Confirm the installed OpenSSH version supports `restrict`. The connector
   sends only a versioned JSON request on stdin. The forced command ignores
   client-supplied remote commands, so use this key only for this probe.
5. Create a private JSON config on the Mac (not in the repository), replace
   the sample values, and set mode `0600`:

   ```json
   {
     "tenant_id": "lab",
     "tenant_name": "Authorized lab",
     "hosts": [
       {
         "host_id": "linux-ops-01",
         "alias": "linux-ops-01",
         "login": "a2z-observe",
         "environments": ["lab"],
         "identity_file": "/Users/you/.ssh/a2z-observe",
         "known_hosts_file": "/Users/you/.ssh/a2z-observe_known_hosts"
       }
     ]
   }
   ```

   `alias` must be a resolvable hostname/IP available on the Mac; the
   connector disables user SSH config, so do not use `~/.ssh/config` aliases.
   DNS must be trusted. The `host_id` is the target value sent to
   `/v1/inventory/observe`.
6. From the package root on the Mac, start the loopback-only read-only API:

   ```bash
   python3 scripts/run-live-ssh-observer-api.py --config /secure/path/ssh-hosts.json
   ```

   The API only binds to loopback. Query it locally using
   `POST /v1/inventory/observe` with `connector_id: "ssh-readonly"`, the
   configured tenant, host ID, and environment. Do not expose this unauthenticated
   development API on a LAN or overlay interface.

The connector pins host keys, disables SSH agent forwarding, TTY and port
forwarding, applies a short timeout, limits response size, and rejects
unknown hosts/tenants/environments and unrecognized helper operations. It also
requires an operator-owned private key with restrictive permissions, a
non-writable pinned known-hosts file, a trusted system SSH executable, and
enforces stdout/stderr limits while the SSH process is running. The remote probe
accepts only root-managed VirtualBox executables from system directories. SSH
stderr is intentionally not returned to API clients because it can disclose
host details; troubleshoot locally as the operator.

## Ubuntu-hosted goal journal

For Codex goal/task persistence on the Linux control-plane host, use the
separate `a2z-control` forced-command account and
[`GOAL_MCP_SETUP.md`](./GOAL_MCP_SETUP.md). It stores tenant-scoped goal state
on Ubuntu but currently performs no host, VirtualBox, guest, cloud, or
Kubernetes mutations. Do not reuse the read-only observation key for this
account; keep its gateway key separate. No worker is installed yet.

## RustDesk operator path

Install the official RustDesk client on macOS and Linux only if a human needs
desktop access. Configure interactive access approval, a strong unique
one-time password or approved identity method, and disable unattended access
unless a documented operational requirement and compensating controls exist.
Prefer a self-hosted RustDesk relay/server for managed environments and keep
its ports private; validate the current upstream networking and hardening
requirements before firewall changes. Do not give the Codex process a saved
RustDesk password or unattended desktop session. The human remains present,
reviews the screen, and performs/approves consequential GUI actions.

IronRDP is a Rust implementation of the RDP protocol, not a drop-in remote
desktop service to install on Linux as a counterpart to RustDesk. It is not
used by this implementation.

## Not yet enabled: controlled writes and multi-cloud

The SSH connector is not a change executor. VirtualBox start/stop, snapshots,
configuration changes, guest login, cloud/hypervisor/Kubernetes writes, sudo,
provisioning, rollback, and unattended RustDesk control remain disabled.
Enabling any requires, per target system, a separate provider adapter and
least-privilege identity, signed plan-bound approval, policy decision,
isolated runner, bounded operation schema (not arbitrary shell), idempotency,
pre/post-state verification, rollback contract, and durable evidence. The
existing approval/workflow endpoints still dispatch simulation only. This
read-only connector must not be described as the full multi-cloud architecture
being live.
