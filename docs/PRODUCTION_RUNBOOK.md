# Production Runbook

## Reference deployment

### Application

```text
/opt/cloudflare-abuseipdb-blocker
```

### Service account

```text
ip-reputation
```

The service account is a system user and is a member of the group allowed to read the Nginx access log.

### Runtime state

```text
/opt/cloudflare-abuseipdb-blocker/data/reputation.db
```

### Nginx log

```text
/var/log/nginx/roxell.access.log
```

## Systemd service

Reference unit:

```ini
[Unit]
Description=Cloudflare AbuseIPDB IP Reputation Worker
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=oneshot
User=ip-reputation
Group=ip-reputation
WorkingDirectory=/opt/cloudflare-abuseipdb-blocker
ExecStart=/opt/cloudflare-abuseipdb-blocker/.venv/bin/python -m app.main
Environment=PYTHONPATH=/opt/cloudflare-abuseipdb-blocker
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/opt/cloudflare-abuseipdb-blocker/data
ReadOnlyPaths=/var/log/nginx
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
```

## Systemd timer

The reference production timer runs the worker every 15 minutes:

```ini
[Unit]
Description=Run Cloudflare AbuseIPDB IP Reputation Worker every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true
Unit=ip-reputation-worker.service

[Install]
WantedBy=timers.target
```

## Nginx client IP handling

The production Nginx configuration trusts Cloudflare network ranges and uses:

```nginx
real_ip_header CF-Connecting-IP;
real_ip_recursive on;
```

The complete Cloudflare range configuration is intentionally environment-specific and should be maintained from Cloudflare's published IP ranges rather than copied blindly into unrelated environments.

## Daily operational checks

```bash
systemctl status ip-reputation-worker.timer
systemctl list-timers --all | grep ip-reputation-worker
sudo journalctl -u ip-reputation-worker.service -n 100 --no-pager
```

Inspect SQLite:

```bash
sqlite3 /opt/cloudflare-abuseipdb-blocker/data/reputation.db   "SELECT ip,score,decision,blocked_at,expire_at,next_recheck_at,cloudflare_status FROM ip_reputation ORDER BY last_seen DESC;"
```

## Expected worker summary

A healthy run ends with a summary similar to:

```text
Worker summary | new_ips=N | checked=N | skipped=N | failed=0 | allow=N | monitor=N | block=N
Worker completed
```

`failed > 0` causes a non-zero worker exit code.

## Incident handling

### AbuseIPDB unavailable

Expected behavior: the affected IP is not automatically blocked. The error is recorded and the worker continues with other IPs.

### Cloudflare unavailable

Expected behavior: the affected block operation fails safely and the error is recorded. Investigate the Cloudflare API response and worker logs before retrying.

### Worker repeatedly failing

1. Stop the timer if necessary.
2. Review journal logs.
3. Validate `.env` permissions and values without exposing secrets.
4. Run the worker manually as `ip-reputation`.
5. Run the automated test suite from a development copy.
6. Re-enable the timer after the root cause is understood.

### Accidental block

Use the Cloudflare list item ID stored in SQLite to identify the item. If the IP is no longer considered block-worthy during lifecycle recheck, the worker can release it automatically; for urgent correction, remove it from the IP list using the approved operational procedure.

## Backup

Back up `data/reputation.db` before major code or policy changes if preserving local lifecycle history matters. Do not back up `.env` into Git or public artifacts.

## Current production validation

The deployed production worker has been manually executed successfully and is scheduled through a systemd timer. The production test suite previously passed 51/51 tests.

The reference project archive used for packaging also contained development/manual scripts that were unsafe for default pytest collection. Those scripts are intentionally excluded from the clean GitHub test suite.
