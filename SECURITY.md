# Security Boundary

The control plane is deny-by-default. Observation, planning, authorization,
execution, verification, and evidence are separate stages.

The local reference core has no provider credentials, production connector, or
mutation executor. By default it makes policy decisions and produces
replayable plans without access to a customer environment. An explicitly
configured `SSHReadOnlyConnector` can make a live connection to registered
Linux hosts for a narrow, forced-command inventory probe. This connector is
read-only and is not a provider or production control path.

Third-party skills remain quarantined until SkillSpector, provenance, policy,
signature, and human-approval gates pass. A clean static report is not a
sandbox and never grants runtime permissions.

Production systems require an isolated runner, task-scoped credentials,
explicit approval, verification, rollback evidence, and tenant-scoped audit
records. Classified or regulated enclaves require separate authorization and
are not connected by this repository.
