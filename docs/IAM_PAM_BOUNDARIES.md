# IAM and PAM Boundaries

Phase 3 separates identity evaluation, session evidence, and emergency access:

- `WorkloadIdentityBroker` evaluates requests but never mints credentials in
  the local core.
- `SessionGateway` records tenant-scoped open/close events and never exposes
  credential material.
- `BreakGlassService` requires two distinct approvers, a bounded expiry, and
  post-review. It returns a conditional decision only; it does not grant
  access.

OIDC, SAML, SCIM, Keycloak, Entra, Okta, PAM, HSM, and workload-provider
adapters remain connector implementations behind these boundaries.
