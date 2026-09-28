# Controlled change workflow

The local API now composes the Phase 2 control sequence around the existing simulated lifecycle:

1. Create a mutation request for a registered tenant identity and asset.
2. Start a plan-bound workflow. PostgreSQL stores the lifecycle snapshot in
   `change_plans.plan`; verified approval foreign keys therefore resolve to a
   durable plan row.
3. Submit an Ed25519 signed approval whose scope exactly binds tenant, target, action, environment, capabilities, and plan identifier. The configured verifier must accept the signature; approvals expire within 15 minutes.
4. Record the verified approval against the matching request and tenant. Production policy requires a distinct second approver.
5. Dispatch only through the existing lab/development simulation lifecycle.
6. Compare expected and observed state after dispatch; failed verification enters the failed state and permits a rollback record.
7. In PostgreSQL mode, persist each updated workflow snapshot and append its
   hash-chained tenant evidence record in one transaction. Startup rehydrates
   the workflow, including approval identities, simulated receipt, and
   verification result. In memory-only mode, the workflow remains process-local.

Routes are documented in `docs/LOCAL_API.md`. Signature verification fails closed when the configured public-key trust directory or verifier is unavailable. The current runner remains a simulation: it reports zero network calls and no credentials. This does not implement provider mutation or a production runner.
