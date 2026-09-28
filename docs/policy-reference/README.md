# Policy Reference

`policies/skill-gate.json` governs skill ingestion.
`policies/runtime-defaults.json` governs default execution isolation.
The local policy engine in `src/control_plane_core/policy.py` is intentionally
conservative and does not grant provider or production access.
