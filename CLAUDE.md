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
│   ├── UserEnumeration.php   # Block user discovery vectors
│   ├── UpdateChecker.php     # GitHub-based auto-updater
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
