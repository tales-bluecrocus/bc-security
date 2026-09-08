# BlueCrocus Security — CLAUDE.md

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
│   ├── create-release.sh     # Release orchestrator (version bump + tag + push)
│   └── build-zip.sh          # Local ZIP builder (manual upload)
├── .github/workflows/
│   └── release.yml           # CI/CD: v* tag → composer install → ZIP → GitHub Release
├── CLAUDE.md                 # This file (development context)
└── README.md                 # User-facing documentation
```

### Classes

| Class | Responsibility |
|-------|---------------|
| `IpResolver` | Detect real client IP (X-Forwarded-For, X-Real-IP, REMOTE_ADDR) |
| `BruteForce` | Lockout per IP, failed attempt tracking, 429 response, all login hooks |
| `PasswordReset` | Per-IP reset throttle, per-account email cooldown, generic reset response |
| `UserEnumeration` | Block REST API users endpoint, author archives, ?author=N |
| `UpdateChecker` | GitHub Releases auto-updater via Plugin Update Checker |
| `CaptchaProvider` | reCAPTCHA v3 / Turnstile CAPTCHA: JS injection, token verification, fail-open |
| `Database` | Creates/updates `wp_bc_form_logs` table via dbDelta |
| `FormLogger` | Insert/query/clear form submission logs |
| `SpamFilter` | Honeypot injection + keyword filter for Elementor/CF7/Gravity/Formidable |
| `AdminPage` | Settings + Logs admin page with tabs |
| `LogsTable` | WP_List_Table subclass for log display with pagination and filters |

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
| `login_form_lostpassword` | action | Throttle gate before wp-login processes the reset POST |
| `login_form_retrievepassword` | action | Same gate — core aliases both action names |
| `lostpassword_post` | action | Count the reset attempt, apply per-account cooldown |
| `lostpassword_errors` | filter | Genericize "no such account" into the success response |
| `retrieve_password_key` | action | Reset mail is going out — start the account cooldown |

## Constants

```php
BC_MAX_ATTEMPTS    = 5    // failures before lockout
BC_LOCKOUT_SECONDS = 900  // 15 minutes

BC_RESET_MAX_ATTEMPTS      = 3    // reset requests per IP before throttling
BC_RESET_WINDOW_SECONDS    = 900  // per-IP window and throttle duration
BC_RESET_COOLDOWN_SECONDS  = 900  // minimum gap between reset emails per account
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

## How password reset protection works

Handled by `PasswordReset`, covering `wp-login.php?action=lostpassword`. Two independent
controls plus an anti-enumeration filter:

```
POST lostpassword ──> login_form_lostpassword ──> per-IP throttle (429 after 3)
                 └──> lostpassword_post       ──> per-account cooldown (silent)
                 └──> lostpassword_errors     ──> unknown account => fake success
```

- **Per-IP throttle** — 3 requests per IP, then HTTP 429 + `Retry-After` for 15 minutes.
  Overt, because a rate limit reveals nothing about any account.
- **Per-account cooldown** — one reset email per account per 15 minutes, keyed on the
  resolved user ID. Enforced **silently**: the request still redirects to
  `?checkemail=confirm`, it just sends no mail. A visible error here would confirm the
  account exists.
- **Generic response** — an unknown account gets the same `302 …?checkemail=confirm` as a
  real one, closing the enumeration oracle WordPress ships with.

Transient keys are deliberately separate from the brute force lockout:

| Key | Payload |
|-----|---------|
| `bc_pwreset_ip_{md5(IP)}` | `array( 'attempts' => int, 'locked_until' => int )` |
| `bc_pwreset_acct_{user_id}` | timestamp |

### Settings

Stored in `bc_security_settings`:
- `pwreset_protection` (bool, default **true**) — per-IP throttle + per-account cooldown
- `pwreset_generic_response` (bool, default **true**) — hide whether an account exists

Both default on, so existing installs are protected as soon as the update lands without
anyone touching the settings page.

### Logging

Reuses `bc_form_logs` via `FormLogger` with `form_plugin = 'password_reset'` — no schema
change. Block reasons: `pwreset_ip_limit`, `pwreset_cooldown`, `pwreset_unknown_account`.

### Testing

```bash
lando wp transient delete --all
```

Unknown and real accounts must return an identical `302` to `?checkemail=confirm`:
```bash
curl -si -X POST "https://SITE/wp-login.php?action=lostpassword" \
  -d "user_login=nobody@example.com&wp-submit=Get+New+Password" | head -20
```

Throttle — the 4th request must be `429`:
```bash
for i in 1 2 3 4; do curl -so /dev/null -w "%{http_code}\n" \
  -X POST "https://SITE/wp-login.php?action=lostpassword" \
  -d "user_login=REAL_USER&wp-submit=Get+New+Password"; done
```

## Spam protection

### How it works

1. `SpamFilter::inject_honeypot_js()` adds a hidden field to all forms via JavaScript (avoids caching issues)
2. On form submit, validation hooks check: honeypot filled? → blocked. Keyword match? → blocked. Otherwise → sent.
3. All submissions (sent + blocked) are logged to `wp_bc_form_logs` via `FormLogger::log()`

### Form plugin hooks

| Plugin | Validation Hook | Success Hook |
|--------|----------------|--------------|
| Elementor Pro | `elementor_pro/forms/validation` | `elementor_pro/forms/new_record` |
| Contact Form 7 | `wpcf7_spam` | `wpcf7_mail_sent` |
| Gravity Forms | `gform_validation` | `gform_after_submission` |
| Formidable | `frm_validate_entry` | `frm_after_create_entry` |

### Settings

Stored in `wp_options` key `bc_security_settings`:
- `honeypot_enabled` (bool, default true)
- `blocked_keywords` (array, default: seo, marketing, bitcoin, crypto, casino, viagra, forex, backlinks, link building, guest post, cbd, diet pills, weight loss)

### CAPTCHA protection

Optional layer (disabled by default). Supports reCAPTCHA v3 and Cloudflare Turnstile.

Settings stored in `bc_security_settings`:
- `captcha_provider` (string, default 'off'): 'off' | 'recaptcha_v3' | 'turnstile'
- `captcha_site_key` (string)
- `captcha_secret_key` (string)
- `captcha_score_threshold` (float, default 0.5, reCAPTCHA v3 only)
- `captcha_on_login` (bool, default false)

When enabled, CAPTCHA runs as the first check before honeypot and keywords. Fail-open on API errors (other layers still protect). CAPTCHA failure on login does NOT count as a brute force attempt.

### Admin page

Menu: "BlueCrocus Security" (dashicons-shield-alt), capability: `manage_options`
- **Settings tab**: honeypot toggle + keywords textarea
- **Logs tab**: WP_List_Table with status filter, search, pagination (25/page), Clear Logs button

### Database

Table `wp_bc_form_logs` created via `dbDelta()`. Migration tracked by `bc_security_db_version` option. Runs on activation and on `plugins_loaded` with version check.

## Key decisions

- **XML-RPC fully disabled** rather than rate-limited — it supports `system.multicall` which can batch hundreds of auth attempts in one request.
- **Transients over custom tables** — simpler, self-cleaning, no migration needed. Trade-off: not suitable for distributed setups without shared object cache.
- **IP detection checks X-Forwarded-For first** — needed behind reverse proxies (Cloudflare, nginx). The first IP in the chain is used.
- **Hydra tests must use `S=` (success pattern)** — when lockout triggers, the response no longer contains the normal failure string, causing false positives with `F=` pattern.
- **IpResolver is injected** into BruteForce via constructor — allows testing with mock IPs and keeps IP logic separate from lockout logic.
- **Password reset uses its own transient prefix** (`bc_pwreset_ip_`, not `bc_lockout_`) — reset spam from a shared or NAT'd IP must never lock a legitimate client out of logging in. The two counters are independent on purpose.
- **The per-account cooldown is silent, the per-IP throttle is not** — returning "too many requests" for a specific account would confirm that account exists, reopening the enumeration oracle the generic response closes. A per-IP rate limit reveals nothing, so it can be overt.
- **Reset protection is per-account, not just per-IP** — IP-only limiting does nothing against a distributed botnet, which is the actual observed attack. The per-account cooldown is what stops a client's inbox filling up.
- **`lostpassword_errors` must handle two shapes** — core adds `invalid_email` *before* the filter and `invalidcombo` *after* it, so an unknown account arrives either with an error code already set or with an empty error bag and `$user_data === false`.

## Release flow

```bash
./.config/bump-version.sh patch   # 2.0.0 → 2.0.1
./.config/bump-version.sh minor   # 2.0.0 → 2.1.0
./.config/bump-version.sh major   # 2.0.0 → 3.0.0
```

Tag push triggers GitHub Actions → `composer install --no-dev` → rsync clean dist → ZIP → GitHub Release → WordPress auto-detects update via `UpdateChecker::register()`.

### Release scripts (.config/)

| Script | Purpose |
|--------|---------|
| `bump-version.sh` | Parse current version, increment, delegate to create-release.sh |
| `create-release.sh` | Update bc-security.php version, commit, tag, push |
| `build-zip.sh` | Local ZIP build for manual client upload (no GitHub release) |

### Auto-update mechanism

- **Library:** Plugin Update Checker v5.6 (yahnis-elsts)
- **Source:** GitHub Releases (ZIP asset)
- **Config:** `UpdateChecker::register()` → points to `https://github.com/tales-bluecrocus/bc-security/`
- **Detection:** WordPress checks every 12 hours
- **Folder fix:** `upgrader_source_selection` filter ensures extracted folder name matches `bc-security`
