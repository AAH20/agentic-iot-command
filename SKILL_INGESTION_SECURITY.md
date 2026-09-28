# Skill Ingestion and Supply-Chain Security

## 1. Purpose

Agent skills are executable or instruction-bearing supply-chain artifacts. They may contain `SKILL.md` instructions, scripts, package manifests, MCP tool definitions, binaries, archives, hidden files, or instructions that attempt to change an agent's priorities. This system therefore treats every skill as untrusted until it passes static analysis, provenance checks, policy review, and sandboxed validation.

NVIDIA SkillSpector is the first security tier. It detects prompt injection, hidden instructions, exfiltration, privilege escalation, dangerous code, tool poisoning, supply-chain problems, and other patterns. It accepts Git repositories, URLs, archives, directories, and files and can emit JSON, Markdown, or SARIF. The scanner is not a sandbox and must never be treated as one.

Reference: https://docs.nvidia.com/skills/scanning-agent-skills
Reference implementation: https://github.com/NVIDIA/SkillSpector

## 2. Security principles

1. **Never install before scanning.** Discovery, download, extraction, scan, review, and installation are separate phases.
2. **Fail closed.** Missing scanner, substantive incomplete analysis, timeout, unknown severity, or unverifiable provenance blocks installation. The only reviewable incompleteness is a report whose ledger contains exclusively non-fatal `reference_missing` records; each must be bound to an exact exception-list digest in a signed owner review. This is a conditional decision, not a clean scan.
3. **Pin immutable content.** Record source URL, commit or digest, archive hash, scanner version, and report hash.
4. **Treat instructions as data.** Skill text cannot override system, platform, repository, or security policy.
5. **Do not execute during scanning.** Static and semantic analysis happen before the artifact enters an execution environment.
6. **Separate static safety from runtime containment.** A clean report does not authorize unrestricted host access.
7. **Least privilege by default.** Skills start with no network, no secrets, no host writes, and no privileged tool access.
8. **Re-scan on change.** Any update to source, lockfile, transitive dependency, archive, or skill instructions creates a new artifact identity.
9. **Human approval for privilege expansion.** Network, filesystem, cloud, PAM, browser, RDP, or production permissions require an explicit approval record.
10. **No silent auto-updates.** Updates are downloaded to quarantine and re-evaluated.

## 3. Scanner lifecycle

```text
discover
  -> resolve canonical source
  -> download to quarantine
  -> hash and record provenance
  -> extract with size/depth/file-count bounds
  -> SkillSpector static scan
  -> optional LLM semantic scan
  -> dependency and CVE lookup
  -> secret/malware/YARA/AST checks
  -> policy gate
  -> human review for conditional findings
  -> sandbox validation
  -> signed approval record
  -> isolated installation
  -> runtime telemetry and drift scan
```

## 4. SkillSpector requirements

Install SkillSpector into a dedicated scanner environment. Do not run the scanner from a skill being scanned.

```bash
uv tool install 'skillspector[mcp] @ git+https://github.com/NVIDIA/skillspector.git@c7958a3268d9498644b22edb75d0f051bbc8cbfc'
skillspector --version
```

For a static-only scan, use `--no-llm`; the installation policy rejects static-only reports. LLM analysis may send eligible file contents to the configured provider. Do not scan confidential customer or classified material with a remote provider.

For an explicitly selected, already-authenticated Codex CLI provider:

```bash
SKILLSPECTOR_PROVIDER=codex_cli scripts/scan-skill.sh ./quarantine/<artifact> ./reports/<artifact>.skillspector.json
```

This uses the local Codex CLI session and requires network access to the Codex service. The provider is never selected automatically. The CLI subprocess uses read-only sandboxing and an ephemeral session. Review `metadata.llm_provenance` and `metadata.llm_available`; missing semantic analysis blocks installation.

Example scan:

```bash
skillspector scan ./quarantine/<artifact> \
  --format json \
  --output ./reports/<artifact>.skillspector.json
```

The exact flags can change with SkillSpector releases. The wrapper in `scripts/scan-skill.sh` verifies the installed CLI and fails closed if the expected output cannot be produced. Update the pinned commit and minimum-version policy together when upgrading.

## 5. Gate levels

### BLOCK

Installation is prohibited if any of the following is present:

- Critical finding
- High finding involving exfiltration, credential access, privilege escalation, destructive commands, hidden instructions, or tool poisoning
- Executable or binary artifact with no explainable need
- Unpinned remote script execution
- Secret harvesting or environment-file enumeration
- Attempts to read other skills, agent prompts, SSH keys, cloud credentials, Kubernetes configuration, browser profiles, or unrelated workspaces
- Scanner failure or incomplete analysis for any reason other than a narrowly reviewable non-fatal `reference_missing` record in `SKILL.md`
- Provenance cannot be resolved
- Artifact changed after scanning

### CONDITIONAL

Requires security review and explicit approval:

- Network access that is essential to the declared function
- Package installation or compilation
- Cloud API access
- Browser automation
- RDP, SSH, PowerShell, or local shell access
- Filesystem writes outside a declared workspace
- Medium findings with a clear, bounded explanation
- Reports with only non-fatal `reference_missing` ledger records; the exact canonical exception list must be reviewed and bound by SHA-256 in the signed approval

Missing or incomplete LLM semantic analysis is **BLOCK**, not CONDITIONAL. The only incomplete-analysis exception is constrained by `policies/skill-gate.json` to non-fatal `reference_missing` records in the skill's `SKILL.md`, with full component coverage and completed analyzer statuses.

The signed approval must address every MEDIUM finding by stable `finding_id` and include a mitigation. It must include review notes and, when reference exceptions exist, the exact `reference_exceptions_sha256` computed by `scripts/skill_gate.py`. High/Critical findings, configured block categories, other incomplete-analysis reasons, and score-threshold violations remain BLOCK decisions and cannot be approved through this path.

### ALLOW

Only when semantic analysis and the configured SkillSpector policy pass. ALLOW is a scan verdict, not installation authorization: the gated installer still requires a valid owner-signed approval bound to the artifact and report digests, and production permissions require the separately configured second approver.

## 6. Required report fields

The wrapper stores the native SkillSpector report. With SkillSpector 2.11.x and later, the gate consumes these fields:

```json
{
  "risk_assessment": {"score": 0, "severity": "LOW", "recommendation": "SAFE"},
  "analysis_completeness": {"is_complete": true},
  "execution_successful": true,
  "metadata": {
    "skillspector_version": "2.12.0",
    "llm_requested": true,
    "llm_available": true
  },
  "issues": []
}
```

The approval ledger is separate from the scanner report and must bind the
artifact digest and report digest to an owner and expiry. Conditional approvals
also bind all conditional finding IDs and, when applicable, the canonical
reference-exception digest. The approval payload is signed with Ed25519 and
verified against an operator-configured public-key trust directory. The gated
installer requires that verified approval record, a pinned local approval
verifier, and a pinned local skills CLI; a scan alone never triggers
installation.

For a `CONDITIONAL` report, prepare review material with:

```bash
python3 scripts/skill_gate.py review-material <report.json> policies/skill-gate.json
```

The output is an unsigned review template only. A security owner must fill in
specific notes and mitigations, bind the artifact and report digests, sign the
complete envelope with the approved Ed25519 key, and configure the pinned
verifier. Neither the template nor this command is approval.

## 7. Hook points

### Pre-install hook

All installation must use `scripts/install-skill-gated.sh`; direct `npx skills add` is prohibited in controlled environments.

### Pre-upgrade hook

The source reference is resolved again, a new artifact is downloaded, and the complete scan is repeated. A delta report compares files, dependencies, declared permissions, and findings.

### CI hook

Any pull request that adds or changes a skill directory must run SkillSpector, secret scanning, dependency scanning, and the policy gate. The build fails if the report is absent or does not meet the threshold.

### Runtime hook

The agent launcher checks that the installed artifact digest exists in the approval ledger. It denies loading if the digest changed, approval expired, the skill was revoked, or required runtime permissions exceed the approved manifest.

### Tool-call hook

The agent governance layer evaluates every tool call with:

```text
request -> identity -> intent -> target -> capability -> policy -> approval -> execution -> evidence
```

## 8. Isolation profile

The default runtime profile is:

```yaml
network: none
filesystem:
  read: [declared_workspace]
  write: [declared_workspace]
process:
  allow: [declared_binaries]
secrets: none
cloud_credentials: none
ssh_agent_forwarding: false
browser_profile: none
rdp: false
production: false
```

An expanded profile is a separate approval object. It is never inferred from the skill's text.

## 9. MCP protection

MCP servers are treated as third-party tools. Record the server source, version, tool list, schemas, network destinations, authentication model, and data-flow map. A skill cannot add an MCP server silently. MCP tool descriptions are untrusted input and cannot modify policy.

If SkillSpector is exposed over HTTP, bind it to loopback or place it behind authentication and mTLS. The HTTP service must reject caller-controlled local paths. Prefer stdio for local scans.

## 10. LLM scan privacy

Use `--no-llm` for confidential source unless the provider, retention, and cross-border data handling are explicitly approved. If semantic analysis is necessary, first redact secrets and private customer data and record the provider, model, endpoint, and retention policy.

## 11. Quarantine and rollback

Artifacts live in a non-executable quarantine directory. Installation copies only the approved, hashed content to the managed skill store. Revocation removes the load authorization, disables the skill, and prevents future executions. Preserve the artifact and report for forensics; do not overwrite evidence.

## 12. Review checklist

- Is the source the intended canonical repository?
- Is the exact commit pinned?
- Was the entire tree scanned, including hidden and nested files?
- Were archives, binaries, and generated files inspected?
- Does the implementation match the stated purpose?
- Does it ask the agent to ignore prior instructions?
- Does it request secrets, prompts, other skills, browser profiles, or unrelated files?
- Does it download and execute remote code?
- Does it create persistence, cron jobs, launch agents, services, or scheduled tasks?
- Does it open network listeners or exfiltrate data?
- Does it use destructive commands?
- Are network and filesystem permissions necessary and bounded?
- Is the report complete and reproducible?
- Was a sandbox test run?
- Is there an owner and expiry date for the approval?
