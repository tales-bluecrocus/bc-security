# BC Security

WordPress security plugin that protects against user enumeration and brute force attacks.

## Features

### Brute Force Protection

Blocks brute force attacks across all three WordPress authentication vectors:

| Vector | Method | Protection |
|--------|--------|------------|
| `wp-login.php` | POST with `log` + `pwd` | IP rate limit — 5 attempts, 15min lockout |
| XML-RPC | `wp.getUsersBlogs` via `xmlrpc.php` | Disabled entirely |
| JWT Auth | POST to `/wp-json/jwt-auth/v1/token` | IP rate limit — shared with wp-login |

**How it works:**
- After 5 failed login attempts, the IP is locked out for 15 minutes
- The counter is shared between wp-login and JWT (failures on one count toward the other)
- Responds with HTTP 429 (Too Many Requests) and `Retry-After` header
- Successful login clears the counter automatically

**Why is XML-RPC disabled entirely?**

XML-RPC supports `system.multicall`, which allows testing hundreds of passwords in a single HTTP request. Per-request rate limiting is insufficient — an attacker can send 500 passwords per request. The only effective protection is disabling the endpoint.

### User Enumeration Protection

Prevents attackers from discovering valid usernames:

| Vector | Protection |
|--------|------------|
| REST API `/wp/v2/users` | Endpoint removed for unauthenticated visitors |
| Author archives `/author/name/` | 301 redirect to homepage |
| Query parameter `?author=1` | 301 redirect to homepage |

## Requirements

- WordPress 5.0+
- PHP 7.4+
- Composer (for autoload)

## Installation

1. Copy the `bc-security` folder to `wp-content/plugins/`
2. Run `composer install` (or `composer dump-autoload`) inside the plugin folder
3. Activate the plugin in the WordPress admin panel

No additional configuration required. The plugin works immediately after activation.

## Configuration

Constants can be changed in `bc-security.php`:

```php
define( 'BC_MAX_ATTEMPTS', 5 );      // Attempts before lockout.
define( 'BC_LOCKOUT_SECONDS', 900 ); // Lockout duration in seconds (15 min).
```

## Compatibility

- **JWT Authentication for WP REST API** — integrated protection for the `/jwt-auth/v1/token` endpoint
- **Cloudflare / Reverse Proxy** — IP detection via `X-Forwarded-For` and `X-Real-IP`
- **Multisite** — supported via `Network: true` in the plugin header

## Architecture

```
bc-security/
├── bc-security.php          # Bootstrap: plugin header, constants, autoload
├── composer.json             # PSR-4 autoload configuration
├── src/
│   ├── IpResolver.php        # Client IP detection behind proxies
│   ├── BruteForce.php        # Login lockout system (wp-login, XML-RPC, JWT)
│   └── UserEnumeration.php   # Block user discovery vectors
├── CLAUDE.md
└── README.md
```

## How It Works Internally

```
Login attempt
       │
       ▼
  IP locked out? ──yes──> HTTP 429 "Too Many Requests"
       │
      no
       │
       ▼
  Credentials correct? ──yes──> Login OK + clear counter
       │
      no
       │
       ▼
  Increment counter
       │
       ▼
  Reached 5 failures? ──yes──> Lock IP for 15 min
       │
      no
       │
       ▼
  Return normal WordPress error
```

## Storage

The plugin uses **WordPress Transients** to store lockout state:

- Key: `bc_lockout_{md5(IP)}`
- Value: `{ attempts: N, locked_until: timestamp }`
- Expiration: automatic after 15 minutes
- No custom database tables

## Known Limitations

- **Does not persist across deploys** if the object cache is cleared
- **Does not work in distributed setups** without a shared object cache (Redis/Memcached)
- **No progressive lockout** (e.g., 1h after 10 failures, 24h after 20)
- **No email notifications** for brute force attempts

## Changelog

### 2.0.0
- Refactored to PSR-4 class-based architecture
- All code and documentation translated to English
- Namespace: `BcSecurity\`

### 1.1.0
- Added brute force protection across 3 vectors (wp-login, XML-RPC, JWT)
- IP rate limiting with 15-minute lockout
- XML-RPC disabled entirely
- HTTP 429 response with Retry-After header

### 1.0.0
- User enumeration protection (REST API, author archives, query parameter)

## License

GPL-2.0-or-later
