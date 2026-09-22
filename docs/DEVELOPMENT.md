# Development Runbook

## 1. Prepare the environment

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

Clone the repository and create the virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
```

## 2. Configure environment

```bash
cp .env.example .env
chmod 600 .env
```

Set:

- `ABUSEIPDB_API_KEY`
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_LIST_ID`
- Nginx log path
- SQLite path

Start with:

```dotenv
DRY_RUN=true
```

## 3. Run automated tests

```bash
pytest -q
```

The standard suite is offline/deterministic and uses mocks. Do not put live API scripts under a `test_*.py` path because pytest will collect them automatically.

Expected repository suite:

```text
51 passed
```

## 4. Test the decision policy

The intended boundaries are:

```text
79 -> ALLOW
80 -> MONITOR
89 -> MONITOR
90 -> BLOCK
100 -> BLOCK
```

These boundaries are covered by `tests/test_decision.py`.

## 5. Dry-run worker

Use a safe test log or an isolated development environment.

```bash
DRY_RUN=true python -m app.main
```

Confirm:

- Nginx IPs are collected.
- private/non-global addresses are ignored.
- AbuseIPDB failures are recorded.
- BLOCK decisions do not modify Cloudflare.
- SQLite state is updated.

## 6. Live integration testing

Live API tests are intentionally not part of `pytest -q`.

For Cloudflare:

- use a documentation-only test IP such as `192.0.2.10`;
- add it to the test IP list;
- wait for the bulk operation;
- verify it exists;
- remove it;
- verify removal.

For AbuseIPDB:

- use an IP you are authorized to query;
- do not commit the result or API key.

## 7. Production cutover

Only after tests and dry-run validation:

```dotenv
DRY_RUN=false
```

Verify configuration:

```bash
python -c 'from app.config import load_settings; print(load_settings())'
```

Do not print secrets in shared terminals or logs.

## 8. Systemd

Validate units:

```bash
sudo systemd-analyze verify /etc/systemd/system/ip-reputation-worker.service
sudo systemd-analyze verify /etc/systemd/system/ip-reputation-worker.timer
```

Reload and enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ip-reputation-worker.timer
```

Manual execution:

```bash
sudo systemctl start ip-reputation-worker.service
sudo journalctl -u ip-reputation-worker.service -n 100 --no-pager
```

Timer:

```bash
systemctl status ip-reputation-worker.timer
systemctl list-timers --all | grep ip-reputation
```

## 9. Rollback

If the worker behaves unexpectedly:

```bash
sudo systemctl stop ip-reputation-worker.timer
```

Then inspect:

```bash
sudo journalctl -u ip-reputation-worker.service --since "1 hour ago"
```

Cloudflare blocks already added to the IP list are independent of the worker process. Remove or release them through the lifecycle process or Cloudflare dashboard according to the incident procedure.
