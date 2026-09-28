# Deployment

Deployment targets are separated by trust boundary: local development,
private cloud, air-gapped, disaster recovery, and regulated environments.
No deployment manifest here opens management ports or carries credentials.

The source now includes a staged installer and systemd service/socket units
for a local grant signer, but no active signer configuration or key. The signer is intentionally
scoped to a single lab tenant, runner, VM target, operation, and short runtime.
It is not an independently authorizing policy service; the API process remains
trusted. The installer installs code and stopped/disabled unit files only; it
does not reload systemd, enable/start services, or generate keys. Do not start
the socket until its dedicated identity and exact
ownership/mode layout are created, the Linux peer-credential path is tested,
and the user has selected a disposable VM after read-only inventory. The
execution switch must remain disabled during installation and validation.

The runner-facing API also has a staged Ubuntu installer,
`scripts/install-worker-api-linux.sh`, a loopback-only mTLS unit, and a strict
runner-certificate registry. Its config/trust directories must be provisioned
from real host identities and reviewed key material; example fingerprints and
VM IDs are placeholders. The installer installs stopped files only and does
not create TLS material or public keys. See
`docs/WORKER_API_SERVICE_DEPLOYMENT.md`; neither installer deploys a worker
executor or observer.
