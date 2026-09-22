# Manual / Live Tests

These tests are intentionally excluded from the default automated test suite.

They may contact real external services or depend on a production-like filesystem.

Run them only after reviewing the script and confirming that:
- credentials are loaded securely;
- the target Cloudflare list is the intended test list;
- test IPs are safe;
- production enforcement is not unintentionally modified.

The default CI suite must remain offline and deterministic.
