# Automating IP Reputation Blocking with Nginx, AbuseIPDB, and Cloudflare

**A practical security-engineering pattern for turning passive IP reputation data into controlled edge enforcement**

IP reputation is useful, but reputation data alone does not protect an application.

A common pattern is:

> Nginx sees an IP → a reputation service scores it → the security engine makes a decision → the edge blocks the IP.

The interesting engineering challenge is everything around that decision: caching, state, asynchronous APIs, lifecycle management, failure handling, and making sure the security automation does not become a new source of outages.

This project implements that pattern using **Nginx, Python, SQLite, AbuseIPDB, and a Cloudflare IP list**.

---

## The architecture

The production flow is deliberately asynchronous:

```text
Internet
   |
   v
Cloudflare
   |
   v
Nginx
   |
   +----> access log
             |
             v
       Python worker
             |
       +-----+------+
       |            |
       v            v
    SQLite       AbuseIPDB
       |            |
       +-----+------+
             |
             v
        Decision Engine
       /      |       \
    ALLOW  MONITOR   BLOCK
                       |
                       v
               Cloudflare IP List
                       |
                       v
                Existing WAF Rule
                       |
                       v
                     BLOCK
```

The worker never calls AbuseIPDB or Cloudflare in the HTTP request path.

That matters.

If the reputation API becomes slow or unavailable, the web application should not suddenly become slow or unavailable.

---

## Why Nginx first?

The application already has an HTTP request path. The simplest observation point is the Nginx access log.

The worker consumes new log entries incrementally rather than rescanning the entire file every 15 minutes.

The collector stores:

- file inode
- byte offset

in SQLite.

That gives the worker enough state to survive:

- normal worker restarts
- log growth
- log rotation
- log truncation

For a first implementation, this is much simpler than introducing Kafka, Redis Streams, or another event pipeline.

---

## The Cloudflare client IP problem

When Cloudflare proxies traffic, Nginx normally sees a Cloudflare edge address as the TCP peer.

The worker needs the real client IP.

The Nginx configuration therefore restores the address using:

```nginx
real_ip_header CF-Connecting-IP;
real_ip_recursive on;
```

The important security detail is that Nginx must trust this header only from Cloudflare network ranges.

Otherwise an Internet client could send its own spoofed forwarding header.

Once the real IP is restored, it becomes the first field of the access log consumed by the worker.

---

## Reputation is not the same as a block decision

The worker uses three states:

| AbuseIPDB score | Decision |
|---|---|
| 0–79 | ALLOW |
| 80–89 | MONITOR |
| 90–100 | BLOCK |

The important part is that the reputation provider is not allowed to directly control the firewall.

There is a decision layer between external intelligence and enforcement.

That gives the security team a place to change policy later without changing the collector or Cloudflare integration.

---

## Why SQLite?

For a single VPS worker, SQLite is enough.

The database stores:

```text
ip
score
decision
first_seen
last_seen
checked_at
blocked_at
expire_at
next_recheck_at
request_count
cloudflare_status
cloudflare_item_id
cloudflare_operation_id
last_error
```

This turns a stateless script into an actual security control.

Without state, every execution would have to rediscover:

- whether an IP was already checked;
- when it was checked;
- whether it is already blocked;
- when the block should expire;
- when the next recheck is due.

---

## Caching matters

The project uses a 24-hour reputation cache for normal IP processing.

That means an IP does not trigger an AbuseIPDB lookup every time it appears in the access log.

This reduces API usage and keeps the worker predictable.

Active blocks are handled differently.

An actively blocked IP does not go through the normal 24-hour pipeline. It enters a lifecycle:

```text
BLOCK
  |
  +--> every 7 days: recheck reputation
  |
  +--> score < 90: release
  |
  +--> score >= 90: keep blocked
  |
  +--> 30 days: release
```

The TTL is important because automated blocking should not become permanent by accident.

---

## Cloudflare enforcement

The worker does not rewrite the entire WAF configuration.

Instead, it manages items in an existing Cloudflare IP list.

The architecture is:

```text
Python
   |
   v
Cloudflare IP List
   |
   v
Existing WAF Custom Rule
   |
   v
(ip.src in $LIST)
   |
   v
Block
```

This separation is useful operationally.

The policy remains visible in Cloudflare, while the automation manages only the dynamic indicators.

Cloudflare list modifications are asynchronous, so the worker:

1. submits the operation;
2. receives an operation ID;
3. polls the operation;
4. verifies the item;
5. records the active state in SQLite.

---

## Failure handling is part of the security design

One of the most important rules in the project is:

> An API failure must not become an automatic block decision.

If AbuseIPDB fails, the worker records the error and does not treat the IP as malicious.

Cloudflare API errors are also handled explicitly.

The Cloudflare client retries transient HTTP 429 and 5xx responses with backoff.

Permanent API errors are surfaced to the worker and stored as operational errors.

---

## Dry-run mode

Before enabling enforcement:

```dotenv
DRY_RUN=true
```

In dry-run mode the worker can execute the collection, reputation and decision pipeline without changing Cloudflare.

Only after validation should the deployment change to:

```dotenv
DRY_RUN=false
```

This is a small feature with a large operational benefit.

---

## Testing

The repository includes a comprehensive automated test suite with 33 deterministic tests.

The test suite covers:

- AbuseIPDB response parsing
- Cloudflare list operations
- Cloudflare retry behavior
- decision boundaries
- block lifecycle
- Nginx log parsing
- incremental collection
- SQLite state
- main worker orchestration
- dry-run behavior
- active-block bypass

External APIs are mocked.

The normal command is:

```bash
pytest -q
```

Live API tests that require real credentials are kept separately in `tests/manual/` and are not part of the default CI workflow.

A CI pipeline should not accidentally:

- call a real reputation API;
- modify a real firewall list;
- write to a production database;
- depend on a production Nginx log.

---

## Production deployment

A reference deployment uses:

```text
Ubuntu
  |
  +-- Nginx
  |
  +-- application directory
  |
  +-- dedicated system user
  |
  +-- systemd service
  |
  +-- systemd timer: every 15 minutes
  |
  +-- SQLite
```

The systemd service runs as a non-login dedicated user with:

```ini
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
```

The worker receives write access only to its runtime data directory and read access to the Nginx log.

---

## Security lessons from the implementation

There are several lessons that are more important than the Python itself.

### 1. Do not put intelligence directly in the request path

External security APIs are dependencies.

Dependencies fail.

Keep them outside the application request path whenever possible.

### 2. State matters

Security automation without state becomes difficult to reason about.

Persist the decisions, timestamps, operation IDs and lifecycle state.

### 3. Automated blocks need an exit strategy

A block should have:

- a TTL;
- a recheck;
- a release mechanism.

Otherwise a temporary intelligence signal can become a permanent firewall rule.

### 4. Test enforcement separately from intelligence

The reputation provider should be mocked when testing the enforcement engine.

Cloudflare should also be mocked in unit tests.

Live API tests belong in a separate, explicitly controlled integration procedure.

### 5. Protect the origin

Cloudflare enforcement is much stronger when the origin cannot simply be reached directly.

Origin firewall restrictions are therefore an important follow-up hardening step.

---

## What I would improve next

The current implementation is intentionally an MVP.

The next engineering steps would be:

1. Origin firewall lockdown.
2. More structured JSON logging.
3. Metrics for checked, blocked, released and failed IPs.
4. Alerting on worker failures.
5. Better API retry handling for AbuseIPDB.
6. IPv6 support.
7. A small dashboard for block lifecycle and reputation trends.
8. Centralized state if the architecture grows beyond one worker.
9. Policy versioning so a decision can be traced to the exact threshold configuration.
10. Integration with a broader security intelligence pipeline.

The key is not to add complexity before the operational need exists.

A single VPS, SQLite and a systemd timer can already provide a useful automated edge-security control when the lifecycle and failure modes are designed carefully.

---

## Closing

The interesting part of this project is not the `requests.get()` call to AbuseIPDB or the Cloudflare API endpoint.

The interesting part is the control plane around them:

```text
Observe
   ↓
Normalize
   ↓
Reputation
   ↓
Decision
   ↓
Enforce
   ↓
Recheck
   ↓
Release
```

That pattern is reusable far beyond IP reputation.

It is the same basic idea behind many security automation systems: collect evidence, make a controlled decision, enforce it at the appropriate layer, and make sure the control can recover safely.
