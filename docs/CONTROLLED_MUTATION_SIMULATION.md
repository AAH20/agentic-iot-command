# Controlled Mutation Simulation

The local lifecycle exercises the control loop without touching infrastructure:

```text
plan -> approval_pending -> approved -> simulated dispatch -> verification
                                                    \-> failed -> rollback
```

Run the tests with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/unit -v
```

The simulated runner always reports `simulation=true`,
`credentials_issued=false`, and `network_calls=0`. It refuses production and
regulated targets even when the approval state is complete. Real runners must
be separate implementations with their own isolation, capability-token,
rollback, and verification controls.
