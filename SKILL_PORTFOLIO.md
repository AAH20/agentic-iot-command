# Skill Portfolio for A2Z Agentic Infrastructure Mastery

This is the initial allowlist candidate set for discovery. It is not a blind install list. Every candidate must pass the SkillSpector gate, provenance review, and runtime permission review in `SKILL_INGESTION_SECURITY.md`.

The skills.sh catalog changes over time. Names can have multiple repositories, forks, or duplicate entries. Resolve each name through the skills.sh API and record the stable source/skill ID before installation.

## Discovery and evaluation

```text
find-skills
research
paper-context-resolver
ai-research-explore
skill-eval
skill-creator
writing-skills
agent-governance
compliance-policy-check
```

## Codex, agent, and computer operations

```text
hermes-agent
computer-use
agent-desktop
cmux-cua
agent-rdp
agent-browser
orchestration
concurrent-cached-fetch
agent-harness
langgraph-agents
google-agents-cli-adk-code
agent-admin
use-windows-vm-computer-use-codex
windows-remote-desktop-connection-doctor
```

## Infrastructure-as-code

```text
terraform-skill
terraform
terraform-best-practices
qovery-terraform
iac-scaffold
terraform-style-guide
finops-agent
design-deploy
migration-readiness
architecture-decision-record
aws-architect
aws-diagram
aws-cdk-development
aws-mcp-setup
gcp-to-aws
sdlc-agents-provision-aws
```

## AWS and EKS

```text
aws-database
signing-in-to-aws
wa-review
aws-resilience-modeling
aws-well-architected-review
eks-best-practices
eks-design
eks-operation-review
eks-resilience-checker
hyperpod-node-debugger
aws-observability
aws-health-events
rds-operation-review
eks-upgrade-check
eks-cluster-provisioning
eks-to-agentcore
cost-governance
containerization
incident-response
ddos-guardian
data-platform-pipeline
agentcore-browser
agentcore-pricing
nova-sonic-voice-agent
text-agent-to-nova-sonic-voice
```

## Azure, Microsoft, and identity

```text
microsoft-foundry
entra-agent-id
azure-diagnostics
azure-compute
azure-cloud-migrate
azure-rbac
azure-quotas
azure-upgrade
azure-kubernetes
azure-enterprise-infra-planner
azure-hosted-copilot-sdk
azure-cost
azure-cost-optimization
azure-reliability
airunway-aks-setup
python-appservice-deploy
```

## Kubernetes, OpenShift, and containers

```text
kubernetes
openshift
azure-kubernetes
eks-best-practices
eks-design
eks-operation-review
eks-cluster-provisioning
eks-upgrade-check
eks-resilience-checker
containerization
docker
helm
gitops
kubernetes-security
cluster-debugging
observability
```

Some names may be supplied by different repositories or packs. Do not infer an install source from a slug alone.

## Virtualization and private datacenter

```text
proxmox
vmware
virtualbox
cloudstack
kvm
libvirt
qemu
datacenter-operations
linux-administration
ubuntu-server
ssh
networking
storage
backup
disaster-recovery
capacity-planning
bare-metal
air-gapped-deployment
```

These are search targets. Resolve and scan only results that have a clear canonical source and a useful implementation.

## IAM, PAM, workload, and agent identity

```text
entra-agent-id
azure-rbac
iam-temp-delegation-review
agent-governance
uipath-gov-access-policy
privileged-access
secrets-management
key-management
fido2
passkeys
oidc
saml
scim
workload-identity
spiffe
policy-as-code
pii-and-compliance
```

## Compliance, security, and audit

```text
infrastructure-compliance-auditor
compliance-policy-check
pii-and-compliance
iam-temp-delegation-review
security-scan
aws-well-architected-review
wa-review
audit
risk-assessment
incident-response
supply-chain-security
sbom
vulnerability-management
secrets-management
policy-as-code
infrastructure-as-code
change-management
disaster-recovery
```

## Agent safety, quality, and continuous evaluation

```text
agent-governance
compliance-policy-check
skill-eval
systematic-debugging
diagnose
qa
verification-before-completion
test-driven-development
code-review
receiving-code-review
requesting-code-review
full-output-enforcement
loop-me
writing-plans
executing-plans
dispatching-parallel-agents
subagent-driven-development
git-guardrails-claude-code
setup-pre-commit
resolving-merge-conflicts
```

## Voice and embodied control

```text
nova-sonic-voice-agent
text-agent-to-nova-sonic-voice
voice-agent-on-aws
computer-use
agent-desktop
cmux-cua
agent-rdp
hermes-agent
langgraph-agents
orchestration
agent-governance
```

## Observability, FinOps, data, and BI

```text
aws-observability
azure-diagnostics
azure-reliability
hyperpod-node-debugger
data-platform-pipeline
data-platform
data-engineering
data-quality
data-lineage
business-intelligence
dashboard
reporting
incident-response
cost-governance
azure-cost
azure-cost-optimization
finops-agent
```

## Demonstration and programmatic video

```text
hyperframes
hyperframes-cli
hyperframes-core
hyperframes-animation
hyperframes-keyframes
hyperframes-audio
hyperframes-registry
remotion-best-practices
remotion-to-hyperframes
embedded-captions
product-launch-video
faceless-explainer
motion-graphics
general-video
video-edit
screenshot
pptx
pdf
design-taste-frontend
high-end-visual-design
visualization
business-intelligence
```

## Recommended source packs to inspect first

```text
vercel-labs/skills
aws/agent-toolkit-for-aws
aws-samples/sample-apex-skills
aws-samples/sample-well-architected-skills-and-steering
aws-samples/sample-agent-skills-for-builders
aws-samples/sample-finops-agent
antonbabenko/terraform-skill
terramate-io/agent-skills
github/awesome-copilot
nousresearch/hermes-agent
manaflow-ai/cmux
lahfir/agent-desktop
borghei/claude-skills
thisnick/agent-rdp
nvidia/skillspector
```

## Search procedure

Use semantic searches, deduplicate by stable ID, and retain the source URL:

```text
agent orchestration computer use remote desktop
terraform opentofu infrastructure as code compliance
aws azure gcp cloud operations
kubernetes openshift proxmox vmware cloudstack
iam pam identity governance secrets
voice agent smart glasses
security audit policy governance
observability finops incident response
```

The catalog API returns a stable ID, source, install URL, skill URL, install count, and optional audit result. A candidate is not installable merely because it appears in a search result.

## Installation order

1. `nvidia/skillspector`
2. `find-skills`
3. `agent-governance`
4. `terraform-skill` and `terraform-best-practices`
5. `infrastructure-compliance-auditor`
6. `computer-use` or `agent-desktop` for the Mac lab
7. `agent-rdp` only for authorized Windows demonstrations
8. AWS/Azure/Kubernetes domain packs
9. virtualization and provider-specific connectors
10. voice and visualization skills

Every step must use the gated installer and generate an approval report.

