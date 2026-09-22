# Nginx deployment notes

The production Nginx server must:

1. Proxy the application as normal.
2. Log the client IP as the first access-log field.
3. Trust only Cloudflare source networks for `CF-Connecting-IP`.
4. Use `real_ip_header CF-Connecting-IP`.
5. Use `real_ip_recursive on`.

Keep the actual certificate paths, hostname, upstream application and current Cloudflare IP ranges environment-specific.
