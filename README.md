# BlueCrocus Security

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

### Password Reset Protection

Stops bots from abusing the "Lost your password?" form to spam reset emails at your users:

| Vector | Protection |
|--------|------------|
| Reset request flood from one IP | Throttled after 3 requests — HTTP 429 for 15 minutes |
| Distributed flood targeting one account | One reset email per account per 15 minutes |
| Account enumeration via the reset form | Unknown accounts get the same response as real ones |

**How it works:**
- After 3 reset requests, the IP receives HTTP 429 with a `Retry-After` header
- Each account can only be emailed one reset link every 15 minutes, no matter how many
  different IPs ask — this is what stops a botnet filling a user's inbox
- The cooldown is enforced *silently*: the page still says "check your email", it just
  sends nothing. A visible error would confirm the account exists
- Requests for accounts that do not exist get the identical "check your email" response
- Reset counters are tracked separately from login lockouts, so reset spam can never lock
  a legitimate user out of signing in
- All blocked and sent resets are recorded in the Logs tab

**Why not just remove the "Lost your password?" link?**

Hiding the link does nothing. Bots POST directly to `wp-login.php?action=lostpassword`
and never read the page. The endpoint stays open whether or not the link is visible.

**Why does WordPress leak account existence by default?**

Core replies "There is no account with that username or email address" for unknown
accounts, but redirects to `?checkemail=confirm` for real ones. That difference is a
reliable oracle for confirming which accounts exist, and is typically how a site's users
end up on a target list in the first place.

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

**Admin page** (Settings > BlueCrocus Security):
- **Settings tab** — toggle honeypot on/off, manage blocked keywords list
- **Logs tab** — view all form submissions with status (sent/blocked), filter by status, search by IP

### CAPTCHA Protection (Optional)

Add an extra layer of bot protection with reCAPTCHA v3 or Cloudflare Turnstile.

**Setup:**
1. Go to **BlueCrocus Security** → **Settings**
2. Under "CAPTCHA Protection", select your provider:
   - **reCAPTCHA v3**: Get keys at [Google reCAPTCHA](https://www.google.com/recaptcha/admin)
   - **Cloudflare Turnstile**: Get keys at [Cloudflare Dashboard](https://dash.cloudflare.com/turnstile)
3. Enter your Site Key and Secret Key
4. For reCAPTCHA v3, adjust the Score Threshold (default 0.5)
5. Optionally enable "Protect Login Page"

**How it works:**
- Runs invisibly — no user interaction required
- Checks every form submission before honeypot and keyword filters
- Fail-open: if the CAPTCHA API is down, forms still work (honeypot + keywords still protect)
- All blocked submissions are logged with the reason (e.g., `captcha_score:0.3`)

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

define( 'BC_RESET_MAX_ATTEMPTS', 3 );       // Reset requests per IP before throttling.
define( 'BC_RESET_WINDOW_SECONDS', 900 );   // Reset throttle duration (15 min).
define( 'BC_RESET_COOLDOWN_SECONDS', 900 ); // Gap between reset emails per account.
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
│   ├── PasswordReset.php     # Lost-password throttle + anti-enumeration
│   ├── UserEnumeration.php   # Block user discovery vectors
│   ├── UpdateChecker.php     # GitHub-based auto-updater
│   ├── CaptchaProvider.php   # reCAPTCHA v3 / Turnstile verification
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

Password reset state uses separate keys so it can never interfere with login lockouts:

- `bc_pwreset_ip_{md5(IP)}` — `{ attempts: N, locked_until: timestamp }`
- `bc_pwreset_acct_{user_id}` — timestamp of the last reset email sent

## Known Limitations

- **Does not persist across deploys** if the object cache is cleared
- **Does not work in distributed setups** without a shared object cache (Redis/Memcached)
- **No progressive lockout** (e.g., 1h after 10 failures, 24h after 20)
- **No email notifications** for brute force attempts
- **Password reset responses still differ in timing** — a request for a real account
  performs a `wp_mail()` call, so it takes measurably longer than one for an account that
  does not exist. The response body and status are identical; closing the timing channel
  entirely would require queued sending.

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
