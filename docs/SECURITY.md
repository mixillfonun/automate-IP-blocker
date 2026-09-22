# Security Notes

## Secrets

Never commit:

- AbuseIPDB API keys
- Cloudflare API tokens
- `.env`
- SQLite production databases
- shell history containing credentials

Use a least-privileged Cloudflare API token that can manage the required account IP list. Do not use the global API key.

## Nginx trust boundary

Only trust `CF-Connecting-IP` when the TCP peer is a Cloudflare network range. The Nginx configuration must include the current Cloudflare IPv4/IPv6 ranges for the deployment.

## Origin protection

The reference architecture assumes Cloudflare is the intended public entry point. Direct origin access is a separate hardening concern. Restricting the origin to Cloudflare source networks/firewall policy should be completed before treating the architecture as fully locked down.

## Worker privileges

The worker should:

- run as a dedicated non-login user;
- have read access to the Nginx log;
- have write access only to its runtime state directory;
- not have access to unrelated home directories;
- use `NoNewPrivileges=true`;
- avoid storing secrets in source files.

## Blocking safety

The worker uses a high-confidence threshold for automatic blocking and a TTL/recheck lifecycle. API errors do not become automatic block decisions.

## Data minimization

Only public IPv4 addresses observed in the Nginx access log are sent to AbuseIPDB. Non-global addresses are filtered locally.
