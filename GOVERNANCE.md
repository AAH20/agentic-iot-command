# Governance

## Change classes

| Class | Example | Minimum control |
|---|---|---|
| Observation | inventory or policy read | read-only identity and evidence envelope |
| Plan | Terraform/OpenTofu or Kubernetes plan | typed plan, policy decision, blast-radius estimate |
| Pre-authorized routine operation | idempotent, reversible, verifiable lab task | signed standing policy, exact action/target allowlist, bounded batch and concurrency, maintenance window, isolated runner, postcondition check, evidence |
| Controlled mutation | reversible lab change | signed approval, isolated runner, verification, rollback |
| Production mutation | customer infrastructure change | dual approval, JIT credential, change window, rollback and evidence |
| Break-glass | emergency containment | named authority, time limit, post-event review |

Voice, model output, scanner output, and skill text are never sole approval
factors for high-impact actions.

The pre-authorized routine path is unavailable by default. A policy decision
of `auto_eligible` is not execution permission; it must be followed by verified
plan binding, a current-state check, a bounded worker lease, rollout controls,
verification, and evidence.

## Ownership

Policy, schema, approval, and evidence changes require security ownership.
Connector changes require a domain owner and a least-privilege review.
Production permission changes require a second approver.
