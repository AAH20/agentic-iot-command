# Execution Orchestrator

Dispatches approved plans to disposable runners. The local reference core
supports simulation only and refuses public, production, regulated, or
credential-bearing dispatch.

The local workflow API accepts a dispatch request only after the matching
plan-bound signed approval has moved the lifecycle to `approved`. Successful
dispatch returns a simulation receipt; verification and rollback evidence are
appended to the tenant's evidence chain.
