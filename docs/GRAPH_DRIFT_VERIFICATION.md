# Graph, drift, and verification boundary

This local reference slice implements three architecture services without provider access or mutation:

- `RelationshipGraph` models tenant-scoped identity, asset, and dependency relationships. Nodes and edges must belong to one tenant; queries cannot cross that boundary.
- `DriftDetector` compares desired and observed state using canonical JSON hashes and stable field paths. It produces evidence-oriented drift events and never produces an executable plan.
- `PostChangeVerifier` accepts a simulation receipt, checks tenant/resource scope and simulation invariants, then compares expected and observed state. Failed verification sets `rollback_required` but does not perform rollback.

The local API exposes these contracts at `/v1/graph/nodes`, `/v1/graph/edges`, `/v1/graph/query`, `/v1/drift/evaluate`, and `/v1/verification/evaluate`.

This is intentionally not the production graph database, provider-backed drift service, or execution orchestrator described in the full handoff. Those remain deployment boundaries and are still listed as not implemented where they require external credentials, networks, or production mutation.
