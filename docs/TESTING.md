# Testing

## Automated test suite

The repository includes five deterministic test modules:

| Module | Tests |
|---|---:|
| `test_decision.py` | 5 |
| `test_lifecycle.py` | 5 |
| `test_main.py` | 7 |
| `test_nginx.py` | 8 |
| `test_storage.py` | 8 |
| **Total** | **33** |

All external service behavior is mocked in these tests.

## Manual tests

Live API tests that require real credentials are kept in `tests/manual/` and are not part of the default test collection.

## Test command

```bash
pytest -q
```

No Cloudflare or AbuseIPDB credentials are required for the automated suite.
