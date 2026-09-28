# Threat Model

## Assets

- Cloud credentials and short-lived tokens
- SSH keys, Kubeconfigs, PAM credentials, and HSM references
- Customer data and security telemetry
- Agent prompts, tool definitions, memory, and policy files
- Terraform state and plan artifacts
- Evidence ledger and audit history
- Skill artifacts and approval records
- IP, policy models, connector code, and deployment topology

## Threat actors

- Malicious or compromised skill author
- Typosquatted or dependency-confused package
- Prompt-injection content in a skill, issue, webpage, or tool result
- Compromised MCP server
- Malicious insider or over-privileged integrator
- Stolen workstation or phone
- Compromised cloud account
- Supply-chain attacker
- Accidental operator error
- External attacker reaching a management endpoint

## Primary abuse cases

1. Skill reads `.env`, SSH keys, cloud configuration, browser sessions, or Kubernetes secrets.
2. Skill tells the agent to ignore its safety rules.
3. Skill downloads and executes a remote script.
4. Skill silently adds an MCP server with broad tools.
5. Skill persists through launch agents, cron, systemd, or shell profiles.
6. Agent applies a destructive Terraform plan without approval.
7. Compromised connector mints a broader credential than requested.
8. RDP or SSH endpoint is exposed publicly.
9. Customer evidence is mixed across tenants.
10. A provider update changes behavior without a re-scan.

## Mitigations

- SkillSpector pre-install and pre-upgrade gate
- Immutable artifact pinning and approval ledger
- Quarantine and non-executing static scan
- Disposable execution runners
- Network, filesystem, secret, and process allowlists
- Short-lived capability credentials
- Policy decision before every tool call
- Human and second-factor approval for high-risk mutation
- Append-only signed evidence
- Tenant isolation and customer-owned data boundaries
- Tailscale/private overlay instead of public management ports
- Separate development, staging, production, and regulated enclaves
- External review and periodic credential rotation
- Incident response, revocation, and rollback procedures

## Residual risk

SkillSpector is static analysis and optional semantic analysis. It is not malware detonation, host sandboxing, or proof of benign intent. Binary, encrypted, time-delayed, or novel attacks may evade it. Runtime isolation, least privilege, provenance, and human approval remain mandatory.

