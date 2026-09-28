# Agent Governance

Agent manifests declare tenant, role, allowed tools, artifact digests, and
verified approval state. The tool gateway evaluates every call against that
manifest and the tool definition before any handler could run.

The local core permits only registered, read-only, non-network, non-credential
tools in observe mode. It returns an authorization decision and never invokes
the tool. Mutation, shell, browser, SSH, RDP, cloud, secret, or production
capabilities require a separate approved runner path.
