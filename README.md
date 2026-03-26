# BC Security

WordPress security plugin that protects against user enumeration, brute force attacks, and form spam.

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

### Form Spam Protection

Blocks spam submissions on contact forms with two layers of defense:

- **Honeypot field** — invisible field injected via JavaScript; bots fill it, humans don't
- **Keyword filter** — blocks submissions containing configurable spam keywords (SEO, bitcoin, casino, etc.)

**Supported form plugins:**

| Plugin | Status |
|--------|--------|
| Elementor Pro Forms | Primary — tested across 50+ client sites |
| Contact Form 7 | Supported |
| Gravity Forms | Supported |
| Formidable Forms | Supported |

**Admin page** (Settings > BC Security):
- **Settings tab** — toggle honeypot on/off, manage blocked keywords list
- **Logs tab** — view all form submissions with status (sent/blocked), filter by status, search by IP

## Requirements

- WordPress 5.0+
- PHP 7.4+
- Composer (for autoload)

## Installation

1. Copy the `bc-security` folder to `wp-content/plugins/`
2. Run `composer install` inside the plugin folder
3. Activate the plugin in the WordPress admin panel

No additional configuration required. The plugin works immediately after activation.

**Updates:** The plugin auto-detects new releases from GitHub. Updates appear in the WordPress dashboard like any other plugin.

## Releasing a New Version

```bash
# Bump patch version (2.0.0 → 2.0.1) — auto-commits, tags, and pushes
./.config/bump-version.sh patch

# Bump minor version (2.0.0 → 2.1.0)
./.config/bump-version.sh minor

# Or specify exact version
./.config/create-release.sh 3.0.0

# Build ZIP locally (for manual upload, no release)
./.config/build-zip.sh
```

Tag push triggers GitHub Actions → builds ZIP → publishes GitHub Release → WordPress auto-detects update within 12 hours.

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
│   ├── UserEnumeration.php   # Block user discovery vectors
│   ├── UpdateChecker.php     # GitHub-based auto-updater
│   ├── Database.php          # Table migration (bc_form_logs)
│   ├── FormLogger.php        # Form submission logger
│   ├── SpamFilter.php        # Honeypot + keyword spam filter
│   ├── AdminPage.php         # Settings + Logs admin page
│   └── LogsTable.php         # WP_List_Table for log display
├── .config/                  # Release scripts
│   ├── bump-version.sh       # Semantic version incrementor
│   ├── create-release.sh     # Release orchestrator
│   └── build-zip.sh          # Local ZIP builder
├── .github/workflows/
│   └── release.yml           # CI/CD: tag push → build → GitHub Release
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
- Added GitHub-based auto-update via Plugin Update Checker
- Added release scripts and CI/CD pipeline

### 1.1.0
- Added brute force protection across 3 vectors (wp-login, XML-RPC, JWT)
- IP rate limiting with 15-minute lockout
- XML-RPC disabled entirely
- HTTP 429 response with Retry-After header

### 1.0.0
- User enumeration protection (REST API, author archives, query parameter)

## License

GPL-2.0-or-later
