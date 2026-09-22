# Architecture

## Request and enforcement flow

1. A public client reaches the Cloudflare-proxied hostname.
2. Cloudflare forwards the request to Nginx.
3. Nginx restores the original client IPv4 using `CF-Connecting-IP`.
4. Nginx writes the request to its access log.
5. The systemd timer starts the worker.
6. `NginxCollector` resumes from the persisted inode/byte offset.
7. New public IPv4 addresses are recorded in SQLite.
8. Existing active blocks are skipped by the normal reputation path.
9. New or cache-expired addresses are checked against AbuseIPDB.
10. The decision engine maps the score to ALLOW, MONITOR or BLOCK.
11. BLOCK decisions are added to the existing Cloudflare IP list.
12. The Cloudflare list is referenced by an active WAF/custom rule that blocks matching source IPs.

## State model

```text
UNKNOWN
   |
   v
reputation checked
   |
   +--> ALLOW
   |
   +--> MONITOR
   |
   +--> BLOCK
          |
          v
       ACTIVE
          |
          +--> recheck < threshold --> ALLOW / release
          |
          +--> recheck >= threshold --> ACTIVE
          |
          +--> TTL expiry --> ALLOW / release
```

## SQLite state

`ip_reputation` stores reputation and lifecycle state:

- IP
- score
- decision
- first/last seen
- checked timestamp
- blocked timestamp
- expiry timestamp
- next recheck
- request count
- Cloudflare status/item/operation identifiers
- last error

`collector_state` stores the Nginx log path, inode and byte offset.

## Why SQLite

SQLite is sufficient for a single-worker VPS deployment. It provides durable state without introducing another service. The design can later be migrated to PostgreSQL if multiple workers or centralized reporting becomes necessary.
