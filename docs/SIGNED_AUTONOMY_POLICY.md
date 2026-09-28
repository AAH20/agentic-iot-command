# Signed autonomy policy profiles

The profile verifier accepts an exact JSON envelope:

```json
{
  "profile": { "...": "fields defined by schemas/autonomy-profile.schema.json" },
  "signature": {
    "algorithm": "ed25519",
    "key_id": "operator-2026",
    "signature_base64": "..."
  }
}
```

The signed bytes are canonical UTF-8 JSON of
`{"domain":"a2z.autonomy-profile.v1","profile":PROFILE}` with sorted keys,
compact separators, and ASCII escaping. The domain string prevents a profile
signature from being reused as an action approval. Duplicate JSON keys,
unknown fields, oversized profiles, broad-writable files, wrong time bounds,
unsupported environments, generic command rules, unsafe defaults, and
unbounded limits are rejected. A profile expires within 30 days of `issued_at`.
The signed profile caps affected resources and estimated incremental cost (in
integer micro-USD) globally and per action. A caller/model cannot supply the
impact estimate used for autonomous eligibility; a trusted adapter or plan
analyzer must derive it from the exact plan digest. Missing estimates fail to
approval-required.

Maintenance windows are authority-bearing policy data, not a caller boolean.
A signed profile may include up to 100 absolute UTC windows, each scoped to one
action, exact target IDs, and non-production environments. Each window must
fit within the profile's validity and last no more than eight hours. Legacy
profiles without this optional field have no open windows and therefore cannot
make an action auto-eligible. The evaluator requires the entire task runtime
to fit before the matched window closes; recurring calendar rules and
local-time/DST interpretation are intentionally not accepted.

## Trust configuration

The verifier needs a dedicated, root-owned directory containing only trusted
Ed25519 public keys. The production verifier rejects a trust directory not
owned by root, preventing the unprivileged gateway account from replacing
trusted keys. On Ubuntu it may be readable/executable by the gateway's
dedicated group (for example mode `0750` with root ownership), but it must not
be group-writable or accessible to other users. Set `A2Z_AUTONOMY_TRUST_DIR` to
that directory in the service environment. The key filename is `<key_id>.pem`;
key files may be group-readable but must not be group/other writable. Key IDs
are restricted to letters, digits, dot, underscore, and hyphen. The private signing key must stay
offline or in a separately governed signing service and must never be copied
to the control plane, runner, repository, or Codex prompt.

The code in this handoff verifies signatures; it deliberately does not provide
a private-key signing command or authorize a profile. Policy authors must use
an independently reviewed Ed25519 signing process that signs the exact
domain-separated canonical bytes above. Review and sign the complete profile
out of band. Do not ask the agent to generate or enable its own standing
authority. The included
[`policies/autonomy-defaults.json`](../policies/autonomy-defaults.json) is an
unsigned, disabled template, not an installable profile.

The verifier is invoked as a subprocess using OpenSSL and a private temporary
file; signature verification failure is a hard denial. The profile loader
derives the policy digest from canonical signed content rather than trusting a
JSON `verified` field. Removing the corresponding public key prevents a future
load from verifying. Already-loaded policy objects are not hot-revoked, so a
production service still needs a strongly consistent revocation feed, cache
invalidation, and scheduler/worker-side kill switch before any dispatcher can
be enabled.

## Not yet an authorization system

Signature verification establishes only that a trusted key signed a
well-formed, time-bounded policy. It does not prove the signer was authorized,
that current asset state matches the plan, that the action is safe, or that a
worker has the correct lease. A signed window only bounds when policy may
consider an action; it does not establish the task's current live state. The current
`AutonomyPolicyEngine` is a policy classifier and always reports
`execution_permitted: false`. The local goal journal refuses to queue even
auto-eligible work. Do not enable mutation based on signature verification
alone.
