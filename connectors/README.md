# Connectors

Each connector must provide a versioned `connector-manifest.json`, declared
network destinations, credential requirements, read-only capability, tenant
boundary, health check, and evidence mapping. Connector presence does not
grant access. Credentials are brokered just in time after policy approval.

## SSH live observation (Linux)

The reference implementation now includes `SSHReadOnlyConnector`. It is an
opt-in live connector for host summary, failed-systemd-unit counts, and
VirtualBox registered/running VM inventory. It does not provide arbitrary
command execution, sudo, guest access, cloud-provider access, or mutation.
See [`docs/REMOTE_ACCESS_OPTIONS.md`](../docs/REMOTE_ACCESS_OPTIONS.md) and the
[`VirtualBox-first demo`](../docs/VIRTUALBOX_FIRST_DEMO.md) for setup and scope.
For direct Codex desktop integration, use the stdio MCP bridge and manual
onboarding guide at `docs/CODEX_UBUNTU_VIRTUALBOX_ONBOARDING.md`.
