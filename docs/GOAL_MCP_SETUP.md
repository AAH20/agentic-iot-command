# Connect Mac Codex to the Ubuntu control-plane host

The goal database belongs on Ubuntu, not the Mac. The intended path is:

```text
Codex MCP client on macOS
  → pinned SSH, no forwarding/TTY
  → one forced command on Ubuntu (a2z-control account)
  → goal/task SQLite database on Ubuntu
```

The Mac MCP client only proxies six named goal/task tools. Ubuntu owns the
tenant, operator identity, baseline guardrails, signed-policy trust roots, and
durable database. The SSH account has no sudo and no VirtualBox permissions.
This gateway persists and evaluates task requests; it is not a worker and has
no VM/cloud mutation path. The separate VirtualBox inventory connector remains
read-only. This distinction keeps Codex's goal-setting interface from becoming
an arbitrary remote shell.

## Prepare Ubuntu after you open the machine

First follow the host identity, pinned SSH, and VirtualBox inventory steps in
[`CODEX_UBUNTU_VIRTUALBOX_ONBOARDING.md`](./CODEX_UBUNTU_VIRTUALBOX_ONBOARDING.md).
Do not modify VM state during onboarding. Then, as the Ubuntu administrator:

1. Verify this is the intended Ubuntu 26.04 lab host and that you are authorized
   to administer it. Confirm Python 3.11+ and OpenSSL are present. Do not expose
   SSH to the public Internet; use your private network/overlay.
2. Create a dedicated `a2z-control` account and same-named primary group, with a usable shell for the
   SSH forced command, public-key-only SSH authentication, no sudo, and no membership in groups
   that can access VirtualBox devices or VM files. This account is only for
   writing the control-plane goal journal.
3. Install the reviewed package files as root-owned, non-writable code beneath
   `/opt/a2z-control-plane/`: `scripts/mcp_goal_journal.py`,
   `scripts/verify-autonomy-profile.sh`, `scripts/verify-approval.sh`, and the modules `goals.py`, `approval.py`,
   `autonomy.py`, `autonomy_catalog.py`, `autonomy_profiles.py`, and
   `__init__.py` under `src/control_plane_core/`. Keep code directories
   root-owned and not writable by `a2z-control`.
   After transferring the package through a trusted private path and verifying
   its reviewed release/checksum, run from the package root:

   ```bash
   sudo bash scripts/install-goal-gateway-linux.sh
   ```

   The installer refuses an existing destination, requires the dedicated
   account, checks its shell and sensitive groups, and installs only the
   non-executing gateway/config. It does not edit sshd or create a key.
4. Create `/var/lib/a2z-control-plane` owned by `a2z-control`, mode `0700`.
   Install `config/goal-gateway-server.example.json` as
   `/etc/a2z-control-plane/goal-gateway.json`, owned by `root`, group
   `a2z-control`, mode `0640` so the gateway can read but cannot alter its
   governance parameters. Keep autonomy disabled initially, the environment limited to `lab`,
   and the target list empty until read-only inventory has been reconciled.
   The SQLite database is created there with owner-only permissions. The
   installer also creates `/etc/a2z-control-plane/approval-trust` as
   root-owned and gateway-group-readable. Add only reviewed Ed25519 approval
   public keys there as `<key_id>.pem`, owned by root and not group/other
   writable. Keep private signing keys offline.
   The installer also creates a separate
   `/etc/a2z-control-plane/impact-assessment-trust` directory. Do not add a
   key until a separately governed estimator has been reviewed; this key
   authorizes signed cost/blast-radius estimates, not infrastructure changes.
   Assessments bind tenant, task, exact targets, operation, environment, plan
   digest, estimate, source, and a short expiry.
5. Install `scripts/a2z-goal-gateway` at
   `/usr/local/libexec/a2z-goal-gateway`, root-owned mode `0755`. The wrapper
   accepts only `--stdio` and starts the fixed MCP server/config paths; it
   cannot accept caller-selected config, Python module, or command arguments.
6. Generate a new, dedicated Ed25519 SSH key on the Mac for this gateway (do
   not reuse the read-only inventory key). Keep the private key on the Mac.
   Pin the Ubuntu host key only after comparing its fingerprint to the value
   shown at the Ubuntu console through a trusted channel.
7. Add the gateway key to the `a2z-control` account's `authorized_keys` with a
   forced command and all forwarding/PTY disabled. For example, prepend this
   exact restriction to the generated public-key line:

   ```text
   restrict,command="/usr/local/libexec/a2z-goal-gateway --stdio" ssh-ed25519 AAAA... a2z-mac-goal-client
   ```

   Confirm the installed OpenSSH supports `restrict`. Ensure every key allowed
   for this account has the same forced command; do not add a normal shell key.
   Keep the account's `.ssh` directory and `authorized_keys` root-owned and
   not writable by `a2z-control`, so the gateway identity cannot add an
   unrestricted key. Verify effective SSH policy for this account is
   public-key-only with password/keyboard-interactive auth, forwarding, X11,
   and TTY disabled before allowing the client key.
8. Test the remote command manually from the Mac with the dedicated key and
   pinned known-hosts file. It should accept only the JSON-RPC gateway protocol.
   Verify that the Linux database is created under
   `/var/lib/a2z-control-plane`, owner-only, and that no VM state changed.

The wrapper is intentionally installed at the fixed `/opt` and `/etc` paths.
If those destinations already exist, stop and review their ownership/content;
do not overwrite an existing installation. Keep a versioned, reviewed release
and change record before updating it.

## Configure the Mac-side Codex bridge

From the package directory on macOS:

```bash
cp config/goal-mcp-client.example.json "$HOME/.codex/a2z-goal-mcp-client.json"
chmod 600 "$HOME/.codex/a2z-goal-mcp-client.json"
```

Edit the copied file: set `ssh_alias` to a resolvable DNS hostname or IP
address (not an entry that exists only in `~/.ssh/config`),
`ssh_login` to `a2z-control`, and set the exact private-key and dedicated
known-hosts paths. Do not put the private key contents in this JSON. The client
checks key/config permissions, pins host verification, disables agent
forwarding, port forwarding, and TTY, and sends only fixed gateway requests.

In Codex desktop, open **Settings → MCP servers → Add server**, choose
**STDIO**, and configure the local client. The equivalent user-level
`~/.codex/config.toml` entry is:

```toml
[mcp_servers.a2z_goal_journal]
command = "/usr/bin/python3"
args = [
  "/Users/<your-mac-username>/Downloads/2000 workflows/a2z-agentic-control-plane-handoff/scripts/mcp_goal_journal_client.py",
  "--config",
  "/Users/<your-mac-username>/.codex/a2z-goal-mcp-client.json"
]
cwd = "/Users/<your-mac-username>/Downloads/2000 workflows/a2z-agentic-control-plane-handoff"
enabled = true
enabled_tools = ["submit_infrastructure_goal", "propose_infrastructure_task", "evaluate_infrastructure_task", "queue_approved_infrastructure_task", "queue_policy_authorized_infrastructure_task", "get_infrastructure_goal_status"]
default_tools_approval_mode = "prompt"
```

Replace `/usr/bin/python3` if needed with the absolute path to Python 3.11+.
Save and restart Codex, then confirm the MCP server reports only the five
allowlisted tools. Codex desktop, CLI, and IDE share the local MCP config; see
[official Codex MCP setup](https://developers.openai.com/codex/mcp/).

Submit a low-risk goal and verify the returned `goal_id`. For each proposed
task, review the full plan artifact returned by Ubuntu; the service derives its
SHA-256 digest, which is the value bound into a later signed approval. Then query
status and confirm the plan and event chain. Repeat with the same idempotency key and identical
body to confirm the original record is returned. A different body under the
same key must be rejected. Confirm the records persist on Ubuntu after the SSH
process exits and a new Codex session reconnects.

## Critical task approval envelope

For an `approval_required` lab task, an authorized operator signs the approval
offline and supplies the signed JSON envelope to
`queue_approved_infrastructure_task`. The approval object must follow
[`schemas/approval.json`](../schemas/approval.json): `request_id` is the
recorded `goal_id`; `plan_id` is the exact `task_id`; `scope` must contain the
configured tenant, the task's one exact target, operation ID, environment, and
capabilities exactly `task.execute` plus `plan.sha256:<64-lowercase-hex-plan-digest>`.
The Ed25519 signature covers canonical UTF-8 JSON of the `approval` object
(sorted keys, compact separators, ASCII escaping). `key_id` must correspond to
a root-owned `<key_id>.pem` in the Ubuntu approval trust directory. Approval
validity is limited to 15 minutes; an approval ID can be consumed only once.
Do not put private signing keys on Ubuntu or in Codex. This records approval
and queues the task. A source-level, one-shot VirtualBox worker coordinator,
independent postcondition verification logic, and verifier-only mTLS API now
exist, but none are deployed as services. No host mutation is available through
this gateway until the verifier and worker services, source outbox
configuration, and reviewed deployment are complete.

The Ubuntu server config may load a signed Ed25519 policy only when its public
key is in a root-managed trust directory readable by the gateway account but
not writable by its group or other users, and the signed profile's tenant,
profile ID, target set, and environments fit the root-managed local baseline. Keep
autonomy disabled until a separate offline signing process and policy review
are established. Never copy the private signing key to Ubuntu, the Mac MCP
config, or Codex.

The current MCP evaluator holds an exclusive short-lived lease while it
classifies a task and checks the signed profile's exact maintenance windows.
VirtualBox power-on and graceful shutdown are code-classified high impact. An
`approval_required` task may now be queued only with a trusted Ed25519 approval
bound to its exact tenant, single target, operation, environment, task ID, and
SHA-256 plan digest; approval IDs are single-use. Queueing records
`execution_permitted: false`. The journal also exposes
`queue_policy_authorized_infrastructure_task`, which
revalidates the configured signed autonomy profile and exact signed impact
assessment before queueing a bounded, non-production auto-eligible task. The
execution-grant v2 lifecycle rechecks that authorization at worker lease, grant,
and one-shot-permit boundaries. The source includes an authenticated worker
transport, a one-task coordinator, signed receipt outbox, independent
postcondition verification logic, and a narrowly scoped verifier mTLS route.
These are not installed or fully connected: a late-receipt reconciliation
route exists in worker API source but has not had Linux mTLS validation; the
verifier registry loader is wired into the prepared verifier API entrypoint,
but neither that API nor a worker/observer service is installed. Linux
end-to-end validation and supervised worker/observer deployment remain
outstanding. No task submitted
through this gateway can change Ubuntu,
VirtualBox, cloud, Kubernetes, or guest state.
