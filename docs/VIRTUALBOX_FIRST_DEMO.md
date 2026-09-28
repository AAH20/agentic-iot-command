# VirtualBox-first mastery demonstration

This is the first real infrastructure target for the architecture: an Ubuntu
26.04 VirtualBox host and its existing VMs. The first session proves trusted
live inventory and evidence capture while preserving every VM's current state.
Do not begin by starting, stopping, snapshotting, importing, or reconfiguring
VMs.

## What is live now

- SSH transport from the Mac to one explicitly registered Ubuntu host, with
  host-key pinning and a dedicated forced-command key.
- Read-only Linux host and systemd summary.
- Read-only VirtualBox inventory from the Linux account's own
  `VBoxManage list vms` and `VBoxManage list runningvms` view. Each registered
  VM becomes an inventory observation with UUID, display name, and a coarse
  power-state label. Oracle documents these commands as registered and
  currently running VM lists ([`VBoxManage list`](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/vboxmanage-list.html)).
- Tenant-scoped observation evidence in the API ledger. The ledger is in
  memory by default; configure `A2Z_EVIDENCE_LEDGER_PATH` to a private file in
  an existing secured directory if evidence must survive API restarts.

## Not live yet

The reference approval/workflow path still dispatches simulation. The SSH
probe cannot execute arbitrary commands, `sudo`, `VBoxManage startvm`,
`controlvm`, snapshot operations, guest commands, or cloud/provider actions.
RustDesk remains human-operated visual access. These are intentional gates,
not capabilities to turn on by putting broader credentials in the config.

## Before the Ubuntu host is online

1. Pick one lab tenant and label the VirtualBox host `lab`; do not mix customer
   or production VMs into this demonstration.
2. In a human terminal on Ubuntu, record the expected host name, VirtualBox
   version, registered VM count, and running VM count. For the baseline use
   `VBoxManage --version`, `VBoxManage list vms`, and
   `VBoxManage list runningvms`. Confirm which Linux account owns the
   VirtualBox registry; inventory is per-user, so the probe must run as that
   same non-root account.
3. Identify one disposable VM for a later lifecycle demonstration, but leave
   it unchanged during this first inventory phase. Note its owner and whether
   it contains data that must not be touched.
4. Follow the dedicated-user, helper installation, forced-command key, and
   pinned-host-key setup in [`REMOTE_ACCESS_OPTIONS.md`](REMOTE_ACCESS_OPTIONS.md).
   Do not open inbound SSH to the public Internet; use your private overlay or
   an approved private network route.
5. On the Mac, create the private SSH registry JSON with exactly one
   environment per host, then start the loopback-only observer API. To retain
   the evidence ledger across restarts, point it at a file in a pre-created,
   private directory:

   ```bash
   chmod 600 /secure/path/ssh-hosts.json
   A2Z_EVIDENCE_LEDGER_PATH=/secure/path/evidence.jsonl \
     python3 scripts/run-live-ssh-observer-api.py --config /secure/path/ssh-hosts.json
   ```

## First live observation

From a second terminal on the Mac, query only the known host ID and lab scope:

```bash
curl --fail-with-body --silent --show-error \
  -H 'Content-Type: application/json' \
  -d '{"connector_id":"ssh-readonly","tenant_id":"lab","target":"linux-ops-01","environment":"lab"}' \
  http://127.0.0.1:8787/v1/inventory/observe
```

The host ID, tenant, and environment must match the private registry. Compare
the returned host and per-VM observations with the baseline collected locally
on Ubuntu. If counts or running states differ, stop and resolve which Linux
account owns the VirtualBox inventory before proceeding. This loopback API has
no network authentication; do not expose it beyond the Mac. The API records
the observation under the selected tenant. It does not automatically create
graph relationships or infer guest health from VM power state.

## Demonstration sequence after inventory is reconciled

1. Show live host/VM inventory and its evidence record.
2. Register or query the relationship graph for the host-to-hypervisor-to-VM
   topology. Keep VM UUID as the stable resource identity; VM names are labels.
3. Create a desired-state example for the disposable lab VM and demonstrate
   policy evaluation, plan review, signed plan-bound approval, simulation
   dispatch, post-change verification, and evidence replay. This demonstrates
   the governance path without changing VirtualBox state.
4. Before any VM lifecycle operation, build and independently validate the
   runner authorization path, then add a narrow metadata-only canary for
   `virtualbox.vm.set_demo_description`. It may change exactly one enrolled,
   powered-off lab VM from `A2Z-Control-Plane-Unlabeled` to
   `A2Z-Control-Plane-Demo`, with rollback to the former description. This
   operation is classified as routine by code, but the current package has no
   mutation adapter or worker; it cannot run yet. The initial label must be
   established and independently observed under operator supervision, not
   assumed by the plan. Require fresh state, exact UUID/plan binding, bounded
   lease, worker-verified grant, kill switch, independent postcondition check,
   rollback, and durable evidence. Do not implement a generic `VBoxManage`
   command field.
5. Only after that narrow metadata canary passes repeatedly should a separate
   change add a VirtualBox lifecycle adapter. Start with one explicit VM UUID
   and one individually approved action, likely power-on of a preselected
   powered-off disposable VM. Require a fresh observation, plan hash, expiry,
   human approval, execution timeout, post-action state check, and evidence.
6. Add a stop action only later, with an explicit graceful-shutdown policy and
   separately reviewed hard-power-off fallback. Never use hard power-off as
   the default rollback. VM snapshot/restore changes need their own capacity,
   consistency, retention, and recovery review.

## Evidence to capture

- Authorized host scope and SSH host-key identity (never the private key).
- Inventory request/response hash, capture time, tenant, and connector version.
- Expected versus observed VM count and running-state reconciliation.
- Graph node/edge IDs for host and VM resources, when manually registered.
- Policy decision, plan digest, signer/approval record, simulation receipt,
  verification result, and evidence-ledger verification output.
- Clear statement that the first run changed no VM or guest state.

Keep raw terminal output and VM names in the lab tenant's retention boundary;
do not collect guest disks, guest logs, credentials, memory, or network packet
captures for this demonstration.
