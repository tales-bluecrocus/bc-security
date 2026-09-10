# BlueCrocus Security

WordPress security plugin that protects against user enumeration, brute force attacks, and form spam.

## Features

### Brute Force Protection

Blocks brute force attacks across all three WordPress authentication vectors:

| Vector | Method | Protection |
|--------|--------|------------|
| `wp-login.php` | POST with `log` + `pwd` | IP rate limit — 5 attempts, then a 15min lockout (or an "I'm not a robot" check, see CAPTCHA) |
| XML-RPC | `wp.getUsersBlogs` via `xmlrpc.php` | Disabled entirely |
| JWT Auth | POST to `/wp-json/jwt-auth/v1/token` | IP rate limit — shared with wp-login |

**How it works:**
- After 5 failed login attempts, the IP is locked out for 15 minutes
- The counter is shared between wp-login and JWT (failures on one count toward the other)
- Responds with HTTP 429 (Too Many Requests) and `Retry-After` header
- Successful login clears the counter automatically
- With CAPTCHA set up, a locked-out connection on `wp-login.php` sees an "I'm not a robot"
  check instead of the lockout, and can keep trying once it's ticked. JWT and other logins
  (WooCommerce, etc.) keep the lockout

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
| Bots submitting the form at all | Optional "I'm not a robot" check (see CAPTCHA) |

**How it works:**
- After 3 reset requests, the IP receives HTTP 429 with a `Retry-After` header
- Each account can only be emailed one reset link every 15 minutes, no matter how many
  different IPs ask — this is what stops a botnet filling a user's inbox
- The cooldown is enforced *silently*: the page still says "check your email", it just
  sends nothing. A visible error would confirm the account exists
- Requests for accounts that do not exist get the identical "check your email" response
- Reset counters are tracked separately from login lockouts, so reset spam can never lock
  a legitimate user out of signing in
- An administrator's "Send password reset" from the Users screen is never throttled
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
- **Settings tab** — toggle honeypot on/off, manage blocked keywords list, CAPTCHA, password reset
- **Logs tab** — view all form submissions with status (sent/blocked), filter by status, search by IP

### CAPTCHA (Optional)

Two separate areas on the settings page. Each stays **off until its keys pass Test Keys**
on the site, so pasting a wrong key can never block anyone.

**Login & password reset** — a visible "I'm not a robot" check:

| Page | When the check appears |
|------|------------------------|
| Sign-in (`wp-login.php`) | Only for a connection that has failed 5 sign-ins, **instead of** the 15-minute lockout. Everyone else never sees it, and the page loads no CAPTCHA script |
| "Lost your password?" | On every request, when switched on |

Provider: **Google reCAPTCHA v2** ("I'm not a robot" Checkbox type) or **Cloudflare
Turnstile** (Managed mode recommended — the widget mode is chosen in Cloudflare's dashboard,
and an invisible-mode widget gives visitors nothing to tick).

**Contact forms** — chosen per site:

| Mode | What visitors see |
|------|-------------------|
| **Off** (default) | Nothing. The honeypot and keyword filter still run |
| **Checkbox** | The login provider's check above the submit button (same keys) |
| **Invisible (reCAPTCHA v3)** | Nothing; Google scores the visit. Needs its own v3 key pair |

To use a form plugin's own CAPTCHA instead, leave this Off and set it up in the form plugin.
Elementor Pro forms that carry Elementor's own configured reCAPTCHA field (v2 or v3) are
always left to Elementor, so no form ever gets two checks.

**Setup:**
1. Create keys for the site: [Google reCAPTCHA](https://www.google.com/recaptcha/admin)
   (v2 "I'm not a robot" Checkbox; v3 "Score based" for Invisible mode) or a
   [Cloudflare Turnstile](https://dash.cloudflare.com/?to=/:account/turnstile) widget
2. Go to **BlueCrocus Security** → **Settings**, paste the keys
3. Click **Test Keys** and complete the check that appears. The status line turns green:
   "Active on {your site}"
4. Save, then choose which pages use it

**Why Test Keys needs you to tick the box:** Google answers a wrong secret key exactly
the way it answers a forged token (`invalid-input-response`), and a wrong site key simply
produces no token. There is no way to tell a broken reCAPTCHA key from a bot on any single
request. The only reliable test is the real thing: your browser produces a genuine token
with the site key, and the site checks it with the secret. Cloudflare, by contrast, does
report a bad secret (`invalid-input-secret`).

Tested keys are remembered per site address. After pushing staging to live, run Test Keys
again on the live site — until then CAPTCHA stays off there. Provider test keys (which
accept everything) are refused.

**When something goes wrong:**

| Situation | Sign-in | Lost password | Contact forms |
|-----------|---------|---------------|---------------|
| Keys never tested, or changed since | Lockout as before | No check | No CAPTCHA |
| Provider unreachable, or reports a fault with our keys | Lockout as before | Let through, admin warned | Let through, admin warned |
| Visitor didn't complete the check, or sent a bad/reused token | Refused: "Please complete the security check" | Refused, same message for any account | Blocked and logged |
| Visitor's browser can't load the CAPTCHA script (ad blocker) | Lockout as before | Refused with a message | Blocked and logged |
| reCAPTCHA v3 score below the threshold | — | — | Blocked and logged |
| Keys stop working after testing (deleted or changed in the console) | Checks fail | Checks fail | Checks fail |

The last row can't be detected on a single request with Google (see above), so the plugin
watches for it: after at least 5 failures and more than an hour with no successful check, a
red notice appears on every admin screen. It only warns; it never switches the check off,
because a bot flood looks exactly the same. CAPTCHA can never lock anyone out of signing
in: the worst case on the login page is the 15-minute lockout that applies without it.

**Scope:** the checkbox covers WordPress's own "Lost your password?" form. WooCommerce's
My Account reset form keeps the rate limits and cooldown but shows no check.

**Conflicts:** if another plugin (Wordfence, Solid Security, Contact Form 7's reCAPTCHA
integration, WPForms and others) is also serving a CAPTCHA, a warning appears in the
settings. Running two on one form makes submissions fail intermittently and consumes double
the monthly quota, without catching more bots.

**Upgrading from 2.2/2.3:**
- Contact-form CAPTCHA is switched **off** on every site
- Existing reCAPTCHA v3 keys move to the contact-form Invisible slot, untested
- Existing Turnstile keys stay in the login & password reset slot, untested
- Nothing uses CAPTCHA until Test Keys passes; the rate limits keep protecting meanwhile
- Sites that used CAPTCHA get a one-time notice explaining this
- The old keys stay in the database until the settings are next saved, so a manual
  downgrade still works

## Requirements

- WordPress 5.5+
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
- **Multisite** — supported via `Network: true` in the plugin header. CAPTCHA keys and Test
  Keys are per subsite

## Architecture

```
bc-security/
├── bc-security.php            # Bootstrap: plugin header, constants, autoload
├── composer.json               # PSR-4 autoload configuration
├── src/
│   ├── IpResolver.php          # Client IP detection behind proxies
│   ├── BruteForce.php          # Login lockout + CAPTCHA escape hatch (wp-login, XML-RPC, JWT)
│   ├── PasswordReset.php       # Lost-password throttle, anti-enumeration, checkbox
│   ├── UserEnumeration.php     # Block user discovery vectors
│   ├── UpdateChecker.php       # GitHub-based auto-updater
│   ├── CaptchaSettings.php     # CAPTCHA defaults and key pairs
│   ├── CaptchaProvider.php     # reCAPTCHA v2/v3 + Turnstile: scripts and verification
│   ├── CaptchaKeyTest.php      # Test Keys: in-browser probe + server check
│   ├── CaptchaVerifiedKeys.php # Which key pairs passed Test Keys on this host
│   ├── CaptchaHealth.php       # Warns when tested keys stop working
│   ├── CaptchaMigration.php    # One-time move from the 2.2/2.3 settings
│   ├── CaptchaConflicts.php    # Detects competing CAPTCHA plugins
│   ├── ElementorCaptcha.php    # Detects Elementor forms with their own reCAPTCHA
│   ├── Database.php            # Table migration (bc_form_logs)
│   ├── FormLogger.php          # Form submission logger
│   ├── SpamFilter.php          # Honeypot + keyword spam filter
│   ├── AdminPage.php           # Settings + Logs admin page, CAPTCHA notices
│   └── LogsTable.php           # WP_List_Table for log display
├── .config/                    # Release scripts
│   ├── bump-version.sh         # Semantic version incrementor
│   ├── create-release.sh       # Release orchestrator
│   └── build-zip.sh            # Local ZIP builder
├── .github/workflows/
│   └── release.yml             # CI/CD: tag push → build → GitHub Release
├── CLAUDE.md
└── README.md
```

## How It Works Internally

```
Login attempt
       │
       ▼
  IP locked out? ──yes──> CAPTCHA active on wp-login? ──no──> HTTP 429 "Too Many Requests"
       │                          │
      no                         yes ──> check completed? ──no──> "Please complete the security check"
       │                                        │
       │                                       yes
       ▼                                        │
  Credentials correct? <────────────────────────┘
       │      └──yes──> Login OK + clear counter
      no
       │
       ▼
  Increment counter
       │
       ▼
  Reached 5 failures? ──yes──> Lock IP for 15 min (or show the check)
       │
      no
       │
       ▼
  Return normal WordPress error
```

## Storage

Login and reset state lives in **WordPress Transients**; form logs use the custom
`wp_bc_form_logs` table.

- Key: `bc_lockout_{md5(IP)}`
- Value: `{ attempts: N, locked_until: timestamp }`
- Expiration: automatic after 15 minutes

Password reset state uses separate keys so it can never interfere with login lockouts:

- `bc_pwreset_ip_{md5(IP)}` — `{ attempts: N, locked_until: timestamp }`
- `bc_pwreset_acct_{user_id}` — timestamp of the last reset email sent

CAPTCHA state lives in options kept apart from the settings, so saving the settings never
clears it:

- `bc_security_captcha_verified` — up to 5 tested key pairs, as hashes (never the secret)
- `bc_security_captcha_health` — failure streaks per key pair
- `bc_security_captcha_schema`, `bc_security_captcha_legacy` — upgrade bookkeeping

## Known Limitations

- **Does not persist across deploys** if the object cache is cleared
- **Does not work in distributed setups** without a shared object cache (Redis/Memcached)
- **No progressive lockout** (e.g., 1h after 10 failures, 24h after 20)
- **No email notifications** for brute force attempts
- **Password reset responses still differ in timing** — a request for a real account
  performs a `wp_mail()` call, so it takes measurably longer than one for an account that
  does not exist. The response body and status are identical; closing the timing channel
  entirely would require queued sending.
- **The reset checkbox covers WordPress's own form only**, not WooCommerce's My Account form.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL-2.0-or-later
