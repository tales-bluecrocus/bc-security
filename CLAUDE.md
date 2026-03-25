# BC Security — CLAUDE.md

## What is this plugin?

WordPress security plugin that protects against two main attack categories:
1. **User Enumeration** — prevents attackers from discovering usernames
2. **Brute Force** — rate-limits login attempts across all authentication vectors

## Architecture

PSR-4 class-based plugin under the `BcSecurity\` namespace.
Uses WordPress transients for lockout state (no custom database tables).
Composer autoload, no other dependencies.

### File Structure

```
bc-security/
├── bc-security.php          # Bootstrap: plugin header, constants, autoload
├── composer.json             # PSR-4 autoload (BcSecurity\ → src/)
├── src/
│   ├── IpResolver.php        # Client IP detection behind proxies
│   ├── BruteForce.php        # Login lockout system
│   └── UserEnumeration.php   # Block user discovery vectors
├── CLAUDE.md                 # This file (development context)
└── README.md                 # User-facing documentation
```

### Classes

| Class | Responsibility |
|-------|---------------|
| `IpResolver` | Detect real client IP (X-Forwarded-For, X-Real-IP, REMOTE_ADDR) |
| `BruteForce` | Lockout per IP, failed attempt tracking, 429 response, all login hooks |
| `UserEnumeration` | Block REST API users endpoint, author archives, ?author=N |

## How the brute force protection works

All three WordPress login vectors share the same lockout counter per IP:

```
wp-login.php  ──┐
XML-RPC        ──┼── BruteForce::record_failed_attempt(IP) ──> transient: bc_lockout_{md5(IP)}
JWT Auth       ──┘
```

- **5 failed attempts** → IP locked out for **15 minutes** (HTTP 429 + Retry-After header)
- Successful login clears the counter
- XML-RPC auth is disabled entirely (`xmlrpc_enabled` = false + methods removed)

### WordPress hooks used

| Hook | Type | Purpose |
|------|------|---------|
| `login_init` | action | Check lockout before wp-login processes POST |
| `wp_login_failed` | action | Record failed attempt |
| `wp_login` | action | Clear attempts on success |
| `xmlrpc_enabled` | filter | Disable XML-RPC |
| `xmlrpc_methods` | filter | Remove auth methods as fallback |
| `rest_pre_dispatch` | filter | Check lockout on JWT token endpoint |
| `jwt_auth_token_before_dispatch` | filter | Record JWT auth failures |
| `authenticate` | filter | Shared lockout check (covers wp-login + JWT) |
| `rest_endpoints` | filter | Remove /wp/v2/users for unauthenticated |
| `template_redirect` | action | Redirect author archives to homepage |
| `parse_request` | action | Block ?author=N enumeration |

## Constants

```php
BC_MAX_ATTEMPTS    = 5    // failures before lockout
BC_LOCKOUT_SECONDS = 900  // 15 minutes
```

Defined in `bc-security.php`. To change, edit the `define()` calls.

## Testing brute force protection

Reset lockouts between tests:
```bash
lando wp transient delete --all
```

Test vectors with Hydra (use `S=` success pattern, not `F=` failure pattern — the 429 response confuses failure-based detection):

```bash
# wp-login.php
hydra -l USER -P passwords.txt TARGET https-post-form \
  "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:S=wordpress_logged_in" -t 4

# JWT Auth
hydra -l USER -P passwords.txt TARGET https-post-form \
  "/wp-json/jwt-auth/v1/token:username=^USER^&password=^PASS^:S=token" -t 4
```

## Key decisions

- **XML-RPC fully disabled** rather than rate-limited — it supports `system.multicall` which can batch hundreds of auth attempts in one request.
- **Transients over custom tables** — simpler, self-cleaning, no migration needed. Trade-off: not suitable for distributed setups without shared object cache.
- **IP detection checks X-Forwarded-For first** — needed behind reverse proxies (Cloudflare, nginx). The first IP in the chain is used.
- **Hydra tests must use `S=` (success pattern)** — when lockout triggers, the response no longer contains the normal failure string, causing false positives with `F=` pattern.
- **IpResolver is injected** into BruteForce via constructor — allows testing with mock IPs and keeps IP logic separate from lockout logic.
