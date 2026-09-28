# Credential Broker

Interface boundary for JIT, tenant-scoped credentials. The local reference
core denies issuance; an implementation must require an approved capability,
identity-bound scope, expiry, revocation, and evidence.
