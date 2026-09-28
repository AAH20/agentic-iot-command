# Local Read-Only Vertical Slice

This slice establishes the first evidence contract without connecting to a
customer environment or using credentials.

```bash
./scripts/inventory-local.sh /path/to/evidence/local-inventory.json [tenant-id]
```

The collector records platform facts, a SHA-256 hostname identifier, and
whether common infrastructure tools are present. It does not invoke those
tools, make network calls, read credentials, or perform mutations. The output
is an `evidence-envelope-v1` document whose payload is hash-linked for later
ledger ingestion.

This is observation only. It is not authorization to run Terraform, kubectl,
cloud-provider clients, VM commands, or any production action.
