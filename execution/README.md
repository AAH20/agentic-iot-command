# Execution Runners

Runners are short-lived and disposable. They receive one task-scoped
capability token, an approved plan, declared inputs, and a rollback contract.

The Mac developer shell is not a production runner. SSH, RDP, cloud CLI,
Terraform, Kubernetes, and virtualization runners remain disabled until their
connector, identity, isolation, and verification contracts are implemented.

The code currently includes a non-executing `RunnerPreflight` library. It
checks signed-grant claims against fresh lease state supplied by an
authenticated lease-source adapter, recomputes the plan digest, enforces
catalog membership and code-owned operation-plan constraints, and checks
lease/grant/runtime expiry. The journal has a separate atomic one-time grant
consumption transition, but it performs no infrastructure action and is not
exposed through an authenticated worker endpoint. No production
authenticated lease-source adapter or operation adapter is implemented, so
no operation is currently authorized to run. See
[`RUNNER_AND_CREDENTIAL_BOUNDARIES.md`](../docs/RUNNER_AND_CREDENTIAL_BOUNDARIES.md).
