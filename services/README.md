# Services

Services are independently deployable control-plane boundaries. They exchange
typed requests and evidence envelopes; they must not share standing customer
credentials or silently invoke connectors.

The policy decision point is authoritative for authorization. The approval
service records approvals. The execution orchestrator may dispatch only an
approved plan to an isolated runner. The evidence ledger is append-only.

The local reference core now composes signed plan-bound approval, simulated
dispatch, verification, and tenant evidence through the controlled change
workflow. Provider runners and durable service deployments remain deployment
adapters described by the architecture.
