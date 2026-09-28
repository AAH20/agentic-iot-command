# Architecture

The system is split into trust zones: public discovery, quarantine,
development, control plane, execution runners, customer environments, and
separate regulated/classified enclaves.

The control loop is:

```text
intent -> typed request -> policy -> approval -> isolated execution -> verification -> evidence
```

The local core implements the typed request and policy stages only. The
service, agent, connector, runner, UI, deployment, and commercial directories
define extension boundaries for later implementations.
