# Monitoring deployment issues

The monitoring server deployment did not run. Two separate problems; neither is a bug in the monitoring playbook, which never executed.

## 1. compose.yaml has no monitoring deployer service

**Symptom:** `docker compose --profile monitoring up -d --build` starts nothing for monitoring.

**Cause:**
- `compose.yaml` defines only the firewall `deployer` service.
- `setup-monitoring` (line 193) tells the user to run the command above, but no service uses the `monitoring` profile.
- `deploy/entrypoint.sh` refers to a `monitoring-deployer` service, but commit a26c743 ("Add monitoring stack and deployer setup") never added it to `compose.yaml`.

**Fix:** add a `monitoring-deployer` service to `compose.yaml` that:
- uses `profiles: [monitoring]`
- sets `PLAYBOOK=deploy/monitoring.yml` and `RETRY_POLICY=always`
- reuses the same build, image, user, `REPO_URL`, `BRANCH`, `INTERVAL`, Git key mounts, `cap_drop` and `security_opt` as `deployer`
- uses its own state volume (not `fw-state`)
- mounts the values written to `.env` by `setup-monitoring`:
  - `MON_SSH_KEY_FILE` -> `/keys/monitoring_key:ro`
  - `MON_KNOWN_HOSTS_FILE` -> `/keys/monitoring_known_hosts:ro`
  - `MON_SECRETS_FILE` -> `/keys/monitoring-secrets.yml:ro`


