# Testing

## Automated test suite

The clean repository includes the seven deterministic test modules that produced the production validation count of 51 tests:

| Module | Tests |
|---|---:|
| `test_abuseipdb.py` | 6 |
| `test_cloudflare_client.py` | 12 |
| `test_decision.py` | 5 |
| `test_lifecycle.py` | 5 |
| `test_main.py` | 7 |
| `test_nginx.py` | 8 |
| `test_storage.py` | 8 |
| **Total** | **51** |

All external service behavior is mocked in these tests.

## What is intentionally not collected

The original production archive contained several top-level scripts named `test_*.py` that perform live API calls, write fixed production-path SQLite files, or depend on the production Nginx log. They are not suitable for normal CI collection.

The clean repository removes those scripts from the default test tree rather than silently changing their behavior.

## Test command

```bash
pytest -q
```

No Cloudflare or AbuseIPDB credentials are required for the automated suite.
