# Manual onboarding: Codex on macOS → Ubuntu + VirtualBox

This checklist prepares Codex to call a **local, read-only MCP tool** on the
Mac. That tool connects to one explicitly enrolled Ubuntu host over pinned
SSH and reports host/VirtualBox inventory. It cannot run arbitrary commands,
start/stop VMs, enter guests, install packages, or administer cloud accounts.
RustDesk is optional for a human-supervised GUI session; it is not needed for
Codex's inventory tool.

Codex's MCP support starts local stdio servers and shares MCP configuration
between the desktop app, CLI, and IDE. The configuration below restricts the
server to two named tools and prompts for approval on every call. See the
[official Codex MCP setup](https://developers.openai.com/codex/mcp/) for the
current UI and configuration options.

## A. On Ubuntu at its local console

Use the same Linux account that owns the current VirtualBox VM registrations.
VirtualBox's registered-VM list is per account. Do not create a new service
account for this first demo unless you intentionally migrate/register the VMs
under that account.

1. Record the current baseline without changing anything:

   ```bash
   whoami
   id
   VBoxManage --version
   VBoxManage list vms
   VBoxManage list runningvms
   ```

   Save the registered and running counts. If these commands fail or show a
   different VM set from the VirtualBox UI, stop and resolve the account issue
   before continuing.

   Keep the UUIDs from both `VBoxManage list vms` and `VBoxManage list
   runningvms` as your operator-owned baseline. The comparison is exact: a
   VM being powered off when it was recorded as running is reported as drift.
   Never copy UUIDs from an example or another machine.

2. Install and start the SSH server only if it is not already available:

   ```bash
   sudo apt update
sudo apt install openssh-server
sudo systemctl enable --now ssh
systemctl is-active ssh
hostname -I
   ```

   Use only an address reachable over a trusted local network or private
   overlay. Do not configure router port forwarding or expose SSH publicly.
   Do not change firewall defaults if you are unsure which interface is
   private; stop and ask for help instead.

3. Read the Ubuntu SSH host-key fingerprint locally:

   ```bash
   sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

   Keep this fingerprint available to compare with the Mac in step B. This is
   the identity of the Ubuntu SSH server, not the Codex client key.

## B. On macOS: create and pin the dedicated client key

Run these commands in Terminal on the Mac. They create a key used only for
this observer; the private key stays on the Mac.

```bash
install -d -m 700 "$HOME/.ssh"
ssh-keygen -t ed25519 -a 64 -f "$HOME/.ssh/a2z-vbox-readonly" -C a2z-vbox-readonly
ssh-add --apple-use-keychain "$HOME/.ssh/a2z-vbox-readonly"
```

Choose a passphrase and keep it in macOS Keychain. The key is constrained by
the forced command on Ubuntu; SSH agent forwarding to Ubuntu is disabled.
If the `ssh-add` option is not available on your macOS version, use its
documented Keychain/agent equivalent and make sure the Codex app's MCP process
inherits `SSH_AUTH_SOCK`. Never paste or upload the private key.

Set a shell variable to the Ubuntu's trusted private address (replace the
example with the address shown by `hostname -I`):

```bash
UBUNTU_PRIVATE_IP=192.168.1.50
ssh-keyscan -t ed25519 "$UBUNTU_PRIVATE_IP" > "$HOME/.ssh/a2z-vbox-known_hosts"
chmod 600 "$HOME/.ssh/a2z-vbox-known_hosts"
ssh-keygen -lf "$HOME/.ssh/a2z-vbox-known_hosts"
```

Compare the fingerprint printed on the Mac with the one read locally on
Ubuntu. **Do not continue if they differ.** `ssh-keyscan` collects a key; it
does not authenticate it by itself. Use the same IP/host spelling in the
registry and the known-hosts entry.

## C. Install the fixed probe on Ubuntu

Transfer only the public probe program from the package to the Ubuntu account.
If SSH is reachable from the Mac and you already have a normal authorized
login for this account, from the package root on macOS run:

```bash
scp -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$HOME/.ssh/a2z-vbox-known_hosts" \
  scripts/a2z-readonly-probe \
  YOUR_UBUNTU_USER@192.168.1.50:/tmp/a2z-readonly-probe
```

Replace both placeholders. If you do not already have a trusted SSH login,
transfer the single probe file using a trusted removable drive or RustDesk
file transfer while a human is present. Do not temporarily expose SSH to the
Internet just to copy it.

On Ubuntu, compare the transferred file's checksum with the Mac's
`shasum -a 256 scripts/a2z-readonly-probe` output, then install it as a
root-owned, non-user-writable helper:

```bash
sha256sum /tmp/a2z-readonly-probe
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -o root -g root -m 0755 /tmp/a2z-readonly-probe /usr/local/libexec/a2z-readonly-probe
```

Only proceed if the hashes match. The helper itself uses fixed read-only
operations (`systemctl --failed` and `VBoxManage list`); it does not use sudo.

## D. Restrict the SSH key to the probe

On Ubuntu, in the **same VM-owning Linux account** identified in step A:

```bash
install -d -m 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
nano "$HOME/.ssh/authorized_keys"
```

Append one line, replacing `AAAA...` with the complete one-line contents of
`~/.ssh/a2z-vbox-readonly.pub` from the Mac. Keep every existing key line:

```text
restrict,command="/usr/local/libexec/a2z-readonly-probe --stdio" ssh-ed25519 AAAA... a2z-vbox-readonly
```

The `restrict` and forced-command options apply to this public key. They turn
any SSH command requested with this key into the fixed probe. Do not add
`sudoers` rules, remove your normal recovery access, or replace the whole
`authorized_keys` file.

## E. Test the constrained SSH path from the Mac

Set `YOUR_UBUNTU_USER` to the account from step A, then send the fixed probe
request. The word `ignored-command` is deliberately not executed; the forced
command must return JSON inventory instead.

```bash
printf '%s\n' '{"version":1,"operations":["host.summary","systemd.health","virtualbox.inventory"]}' |
  ssh -i "$HOME/.ssh/a2z-vbox-readonly" \
    -o IdentitiesOnly=yes -o ForwardAgent=no -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$HOME/.ssh/a2z-vbox-known_hosts" \
    "YOUR_UBUNTU_USER@$UBUNTU_PRIVATE_IP" ignored-command
```

Confirm JSON contains the same VM UUIDs and running states as the Ubuntu
baseline. If it returns an SSH error, a different account's inventory, or
unexpected data, stop; do not broaden the key or switch off host-key checks.

## F. Configure the local Codex MCP tool

1. On the Mac, create private config/evidence directories and a registry file
   at a stable path outside the repository. Use the actual username, IP, key
   paths, and the private directories created here:

   ```bash
   install -d -m 700 "$HOME/.config/a2z" "$HOME/.local/share/a2z"
   ```

   ```json
   {
     "tenant_id": "lab",
     "tenant_name": "Authorized VirtualBox lab",
     "evidence_ledger": "/Users/YOU/.local/share/a2z/vbox-evidence.jsonl",
     "hosts": [
       {
         "host_id": "ubuntu-vbox-lab",
         "alias": "192.168.1.50",
         "login": "YOUR_UBUNTU_USER",
         "environments": ["lab"],
         "identity_file": "/Users/YOU/.ssh/a2z-vbox-readonly",
         "known_hosts_file": "/Users/YOU/.ssh/a2z-vbox-known_hosts"
       }
     ],
     "virtualbox_baselines": {
       "ubuntu-vbox-lab": {
         "registered_vm_uuids": ["REPLACE_WITH_EACH_REGISTERED_VM_UUID"],
         "running_vm_uuids": ["REPLACE_WITH_EACH_RUNNING_VM_UUID"]
       }
     }
   }
   ```

   Replace the example values with canonical UUIDs recorded in step A. Use
   `[]` for an empty list. The baseline is optional and is loaded from this
   owner-only registry at MCP startup; the MCP tools cannot change it. If you
   omit `virtualbox_baselines`, the comparison tool is not exposed.

   After saving the registry as `~/.config/a2z/ssh-hosts.json`, run
   `chmod 600 "$HOME/.config/a2z/ssh-hosts.json"`. The evidence file is
   created owner-only by the ledger. Do not put key material in this JSON.
2. Open the handoff package's `scripts/mcp_virtualbox_observer.py` and note
   its absolute path. Find the Python 3.11+ executable with
   `command -v python3` and `python3 --version`; use that executable's full
   path below.
3. Add the following server to `~/.codex/config.toml` (Codex Settings → MCP
   Servers → Add server is also supported). **Append** it; preserve other
   Codex configuration. Substitute the real paths. TOML quoted strings can
   contain spaces in the package path.

   ```toml
   [mcp_servers.a2zVirtualBox]
   command = "/ABSOLUTE/PATH/TO/python3"
   args = ["/Users/YOU/Downloads/2000 workflows/a2z-agentic-control-plane-handoff/scripts/mcp_virtualbox_observer.py", "--config", "/Users/YOU/.config/a2z/ssh-hosts.json"]
   cwd = "/Users/YOU/Downloads/2000 workflows/a2z-agentic-control-plane-handoff"
   env_vars = ["SSH_AUTH_SOCK"]
   enabled = true
   enabled_tools = ["observe_virtualbox_host", "compare_virtualbox_to_baseline", "verify_inventory_evidence"]
   default_tools_approval_mode = "prompt"
   tool_timeout_sec = 45
   ```

4. Restart Codex. In the desktop composer, use `/mcp` or Settings → MCP
   Servers and confirm `a2zVirtualBox` is connected with the configured
   read-only tools (three when a baseline is present; otherwise two).
   The official Codex docs describe the desktop app's shared MCP configuration
   and restart step ([Codex MCP setup](https://developers.openai.com/codex/mcp/)).
5. Ask Codex: “Use `observe_virtualbox_host` for `ubuntu-vbox-lab`, then use
   `compare_virtualbox_to_baseline` for that host, then call
   `verify_inventory_evidence`. Report all drift and do not change any host or
   VM state.” Approve each read-only MCP tool call when prompted. Comparison
   reports missing/unexpected registered and running UUIDs and appends the
   result to the tenant evidence chain. It does not accept a baseline from the
   tool caller and cannot update the configured baseline.

The MCP process runs locally on macOS. It uses the private SSH registry and
dedicated key to connect to Ubuntu; the Ubuntu key's forced command and the
MCP tool schema independently limit it to inventory. The old loopback HTTP
API is optional for manual experiments and is not required for Codex MCP.

## G. What “Codex takeover” means at this stage

After these steps Codex can request host and VirtualBox inventory and verify
the local evidence chain. It cannot take unrestricted control of Linux, use a
terminal on Ubuntu, operate guests, or alter VM power/configuration. RustDesk
is a human-present visual path only. Any later start/stop capability must be a
separate named MCP tool with a fixed action schema, plan-bound approval,
precondition check, timeout, postcondition verification, and a tested recovery
procedure. Never add an arbitrary `command` or shell tool to this server.

## H. Stop and revoke access

To revoke the connector key, remove only its `a2z-vbox-readonly` line from the
Ubuntu account's `~/.ssh/authorized_keys`, save the file, and confirm the
dedicated SSH test now fails. Disable/remove the `a2zVirtualBox` MCP entry in
Codex and unload the key from the Mac agent with:

```bash
ssh-add -d "$HOME/.ssh/a2z-vbox-readonly"
```

Retain or remove the local private key and evidence file according to your
own retention policy; do not delete evidence needed for audit/replay.
