# API Contracts

API boundaries are represented by JSON Schemas in `schemas/`. Services must
reject unknown versions, incomplete evidence, missing identity, missing
approval, and capability requests outside the approved runtime profile.

Approval records use Ed25519 signatures over canonical JSON. The local API
checks the approval with the configured verifier, validates its expiry, and
requires an exact scope match against the registered request and workflow plan.
Caller-supplied verification flags are not trusted.
