# BlueCrocus Security — CLAUDE.md

## What is this plugin?

WordPress security plugin that protects against two main attack categories:
1. **User Enumeration** — prevents attackers from discovering usernames
2. **Brute Force** — rate-limits login attempts across all authentication vectors

Plus password reset abuse protection, contact-form spam filtering, and optional CAPTCHA.

## Architecture

PSR-4 class-based plugin under the `BcSecurity\` namespace.
Uses WordPress transients for lockout state and options for CAPTCHA state; one custom
table (`wp_bc_form_logs`) for form logs.
Composer autoload, no other dependencies.

### File Structure

```
bc-security/
├── bc-security.php            # Bootstrap: plugin header, constants, autoload
├── composer.json               # PSR-4 autoload (BcSecurity\ → src/)
├── src/
│   ├── IpResolver.php          # Client IP detection behind proxies
│   ├── BruteForce.php          # Login lockout system + CAPTCHA escape hatch
│   ├── PasswordReset.php       # Lost-password throttle, anti-enumeration, checkbox
│   ├── UserEnumeration.php     # Block user discovery vectors
│   ├── UpdateChecker.php       # GitHub-based auto-updater
│   ├── CaptchaSettings.php     # Single source of CAPTCHA defaults and key pairs
│   ├── CaptchaProvider.php     # reCAPTCHA v2/v3 + Turnstile: scripts, verification, key testing
│   ├── CaptchaKeyTest.php      # Test Keys: probe page (admin-post) + token check (ajax)
│   ├── CaptchaVerifiedKeys.php # Fingerprints of key pairs that passed Test Keys
│   ├── CaptchaHealth.php       # Failure streaks → admin warning
│   ├── CaptchaMigration.php    # One-time move from the 2.2 CAPTCHA settings
│   ├── CaptchaConflicts.php    # Detects competing CAPTCHA plugins
│   ├── ElementorCaptcha.php    # Detects Elementor forms with their own reCAPTCHA
│   ├── Database.php            # Table migration (bc_form_logs)
│   ├── FormLogger.php          # Form submission logger
│   ├── SpamFilter.php          # Honeypot + language + keyword spam filter + contact-form CAPTCHA
│   ├── KeywordMigration.php    # One-time addition of new default keywords to saved lists
│   ├── AdminPage.php           # Settings + Logs admin page, CAPTCHA notices
│   └── LogsTable.php           # WP_List_Table for log display
├── .config/                    # Release scripts
│   ├── bump-version.sh         # Semantic version incrementor
│   ├── create-release.sh       # Release orchestrator (version bump + tag + push)
│   └── build-zip.sh            # Local ZIP builder (manual upload)
├── .github/workflows/
│   └── release.yml             # CI/CD: v* tag → composer install → ZIP → GitHub Release
├── CLAUDE.md                   # This file (development context)
└── README.md                   # User-facing documentation
```

### Classes

| Class | Responsibility |
|-------|---------------|
| `IpResolver` | Detect real client IP (X-Forwarded-For, X-Real-IP, REMOTE_ADDR) |
| `BruteForce` | Lockout per IP, failed attempt tracking, 429 response, all login hooks, checkbox for flagged IPs on wp-login |
| `PasswordReset` | Per-IP reset throttle, per-account email cooldown, generic reset response, checkbox on the lost-password form |
| `UserEnumeration` | Block REST API users endpoint, author archives, ?author=N |
| `UpdateChecker` | GitHub Releases auto-updater via Plugin Update Checker |
| `CaptchaSettings` | CAPTCHA defaults, `pair()` (provider/site/secret), `clean_key()`, `home_host()`, `fingerprint()` |
| `CaptchaProvider` | Pair status/gating, widget + v3 scripts, `verify_pair()`, `test_pair()`, config-fault classification |
| `CaptchaKeyTest` | Test Keys: same-origin probe page and the AJAX token check (admin only) |
| `CaptchaVerifiedKeys` | Up to 5 verified fingerprints in `bc_security_captcha_verified` |
| `CaptchaHealth` | Per-pair failure streaks in `bc_security_captcha_health` (capped writes, warning only) |
| `CaptchaMigration` | One-time settings migration, tracked by `bc_security_captcha_schema` |
| `CaptchaConflicts` | Detects other active plugins also serving a CAPTCHA (informational only) |
| `ElementorCaptcha` | Decides when an Elementor form's own reCAPTCHA takes over from ours |
| `Database` | Creates/updates `wp_bc_form_logs` table via dbDelta |
| `FormLogger` | Insert/query/clear form submission logs |
| `SpamFilter` | Honeypot injection + blocked alphabets + keyword filter + contact-form CAPTCHA for Elementor/CF7/Gravity/Formidable; owns `DEFAULT_KEYWORDS` and `SCRIPTS` |
| `KeywordMigration` | Appends new default keywords to a saved keyword list once, tracked by `bc_security_keywords_rev` |
| `AdminPage` | Settings + Logs admin page with tabs, CAPTCHA admin notices, migration notice dismissal |
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
- Once over the limit, the transient is rewritten at most once a minute (no write per request)

### Escape hatch (CAPTCHA on login)

When `CaptchaProvider::is_login_challenge_active()` (setting on **and** the main pair has
passed Test Keys on this host), a flagged IP on `wp-login.php` gets the main checkbox
instead of the lockout:

- `login_init`: a sign-in POST carrying `bc_captcha_token` goes on; anything else gets the
  429 with no password hashing and no DB write.
- `authenticate` (priority 30): `verify_pair('main')`. `captcha_unavailable` → lockout
  error (never an open door). Failure → `bc_captcha_required`, the same message whether or
  not the password was right. Pass → the password verdict stands.
- Not wp-login (JWT, WooCommerce, other front-end logins) → the lockout, as before.
- Rendering (`login_enqueue_scripts`, `login_form`, `login_footer`, `login_message`) only
  when `show_challenge()`; normal sign-ins load no provider script.

### WordPress hooks used

| Hook | Type | Purpose |
|------|------|---------|
| `login_init` | action | Check lockout before wp-login processes POST |
| `wp_login_failed` | action | Record failed attempt |
| `wp_login` | action | Clear attempts on success |
| `login_enqueue_scripts` | action | Load the checkbox script (flagged IP on sign-in; lost-password screen) |
| `login_form` | action | Checkbox container for a flagged IP |
| `lostpassword_form` | action | Checkbox container on the lost-password form |
| `login_footer` | action | Checkbox script (prints before footer scripts at 20) |
| `login_message` | filter | Explain the checkbox to a flagged IP |
| `shake_error_codes` | filter | Shake the form on `bc_captcha_required` |
| `xmlrpc_enabled` | filter | Disable XML-RPC |
| `xmlrpc_methods` | filter | Remove auth methods as fallback |
| `rest_pre_dispatch` | filter | Check lockout on JWT token endpoint |
| `jwt_auth_token_before_dispatch` | filter | Record JWT auth failures |
| `authenticate` | filter | Shared lockout check (covers wp-login + JWT), escape-hatch verification |
| `rest_endpoints` | filter | Remove /wp/v2/users for unauthenticated |
| `template_redirect` | action | Redirect author archives to homepage |
| `parse_request` | action | Redirect `author` and `author_name` lookups (logged-out) — same answer for real and made-up names |
| `oembed_response_data` | filter | Drop `author_url` (carries the login-derived slug); keep `author_name` |
| `wp_sitemaps_add_provider` | filter | Remove core's `users` sitemap |
| `authenticate` (40) | filter | Replace `invalid_username` / `invalid_email` / `incorrect_password` with one generic `incorrect_password` error |
| `login_form_lostpassword` | action | Throttle gate before wp-login processes the reset POST; marks `via_login_form` (priority 1) |
| `login_form_retrievepassword` | action | Same — core aliases both action names |
| `lostpassword_post` | action | Count the reset attempt, verify the checkbox, apply per-account cooldown |
| `lostpassword_errors` | filter | Genericize "no such account" into the success response |
| `retrieve_password_key` | action | Reset mail is going out — start the account cooldown |
| `wp_enqueue_scripts` / `wp_footer` | action | Contact-form CAPTCHA script (only when a forms mode is in force) |
| `admin_notices` | action | CAPTCHA fault, untested keys, health warning, one-time migration notice |
| `admin_post_bc_captcha_probe` | action | Test Keys probe page (iframe) |
| `wp_ajax_bc_test_captcha` | action | Check the probe's token with the typed secret |
| `admin_post_bc_dismiss_captcha_notice` | action | Dismiss the migration notice |

## Constants

```php
BC_MAX_ATTEMPTS    = 5    // failures before lockout
BC_LOCKOUT_SECONDS = 900  // 15 minutes

BC_RESET_MAX_ATTEMPTS      = 3    // reset requests per IP before throttling
BC_RESET_WINDOW_SECONDS    = 900  // per-IP window and throttle duration
BC_RESET_COOLDOWN_SECONDS  = 900  // minimum gap between reset emails per account
```

Defined in `bc-security.php`. To change, edit the `define()` calls. There are deliberately
no wp-config.php overrides or CAPTCHA kill switch (owner's decision): CAPTCHA cannot block
sign-ins, and admins can switch the other surfaces off in the settings.

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
controls, an anti-enumeration filter, and an optional checkbox:

```
POST lostpassword ──> login_form_lostpassword ──> per-IP throttle (429 after 3)
                 └──> lostpassword_post       ──> count attempt, checkbox, per-account cooldown (silent)
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
- **Checkbox** — when `is_reset_active()`, POSTs from wp-login.php's own form
  (`via_login_form`) must pass `verify_pair('main')`. WooCommerce and other front-end reset
  forms call `retrieve_password()` too; they keep the throttle and cooldown but get no
  checkbox, because we never rendered one there.
- **Admin-initiated resets** (`is_admin() && current_user_can('edit_users')`) are skipped
  entirely: core's "Send password reset" runs through the same hooks.

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
change. Block reasons: `pwreset_ip_limit`, `pwreset_cooldown`, `pwreset_unknown_account`,
plus `captcha_missing` / `captcha_failed` from the checkbox.

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

With the reset checkbox active, those requests carry no token and are refused with
`captcha_failed`, but still count toward the throttle (recorded before the check).

## Spam protection

### How it works

1. `SpamFilter::inject_honeypot_js()` adds a hidden field to all forms via JavaScript (avoids caching issues)
2. On form submit, validation hooks check: CAPTCHA (if a forms mode is in force)? → honeypot filled? → blocked alphabet? → keyword match? → otherwise sent.
3. All submissions (sent + blocked) are logged to `wp_bc_form_logs` via `FormLogger::log()`

Block reasons: `honeypot`, `language:{cyrillic|han|arabic}`, `keyword:{keyword}`, plus the
CAPTCHA reasons.

**Blocked alphabets** — `check_scripts()` blocks a submission when any field holds a single
letter matching `SpamFilter::SCRIPTS` (`\p{Cyrillic}`, `\p{Han}`, `\p{Arabic}`). Text PCRE
cannot read (broken UTF-8) is let through.

**Keywords match whole words** — `keyword_pattern()` requires a word edge on each side
where the keyword starts/ends with a letter or digit (so `.xyz` and `#1 on google` still
work), allows a plural `s`/`es`, treats an apostrophe + letter as part of the word, and
lets a space match any whitespace. If PCRE cannot read the text it falls back to `stripos`.

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
- `blocked_keywords` (array, default `SpamFilter::DEFAULT_KEYWORDS` — the only copy, 160 entries)
- `blocked_scripts` (array of `SpamFilter::SCRIPTS` slugs, default all three: `cyrillic`, `han`, `arabic`)

The defaults only apply until the settings page is first saved; after that the site keeps
its own copy. **A new default keyword therefore needs two edits**: `DEFAULT_KEYWORDS` and
`KeywordMigration::ADDED` (raise `REV`), or it never reaches a site with a saved list.
`KeywordMigration::maybe_migrate()` runs at include time after `CaptchaMigration`, appends
the missing words once, skips a list an admin emptied, and records
`bc_security_keywords_rev`.

Unticking every language posts no `blocked_scripts` key, exactly like a settings page
opened before the field existed. The hidden `blocked_scripts_shown` tells them apart: with
it the save means "none"; without it the sanitizer keeps the stored value.

`get_post_text_fields()` unslashes and walks nested values (Formidable posts every answer
as `item_meta[ID]`; checkbox groups are arrays), joining keys with a dot. It skips token fields (`bc_captcha_token`, `bc_captcha_error`,
`g-recaptcha-response`, `cf-turnstile-response`, `_wpcf7_recaptcha_response`): scanned as
text, ~28% of random tokens contain a short keyword (seo/btc/nft/mlm/ico/cbd).

### CAPTCHA

Two key pairs, because Google issues v2 and v3 keys separately:

| Pair | Provider | Used by |
|------|----------|---------|
| `main` | `recaptcha_v2` (checkbox) or `turnstile` | login escape hatch, lost-password form, forms in Checkbox mode |
| `v3` | `recaptcha_v3` | forms in Invisible mode only |

Settings in `bc_security_settings` (defaults in `CaptchaSettings::defaults()` — the only
copy):
- `captcha_main_provider` ('recaptcha_v2'), `captcha_main_site_key`, `captcha_main_secret_key`
- `captcha_login_challenge` (bool, **true** — inert until the main pair is verified)
- `captcha_on_lostpassword` (bool, false)
- `captcha_forms_mode` ('off' | 'checkbox' | 'v3', default 'off')
- `captcha_v3_site_key`, `captcha_v3_secret_key`, `captcha_score_threshold` (0.5)

Separate options (a settings save can never wipe them):
- `bc_security_captcha_verified` — up to 5 `{fp, pair, host, time}`;
  `fp = sha256(host \n pair \n provider \n site \n secret)`. Only the hash is stored.
- `bc_security_captcha_health` — per pair `{fp, fails, streak_start, last_success, last_code}`
- `bc_security_captcha_schema` (int), `bc_security_captcha_legacy` (not autoloaded)

**Adding a CAPTCHA setting requires three edits** or it silently does nothing:
`CaptchaSettings::defaults()`, the current-form branch of `AdminPage::sanitize_settings()`
(rebuilds from scratch — an unlisted key is dropped on every save; the stale-form branch
copies every default key automatically), and an `add_settings_field()` + renderer.

The settings form carries a hidden `_form_rev` (`CaptchaSettings::FORM_REVISION`). A save
without it came from a page opened before the update, and keeps the stored `captcha_*`
values. `captcha_forms_mode` is accepted as a marker too, because WordPress runs the
sanitizer a second time on already-sanitized values when the option is first created.

#### Gating

A surface is enforced only when its pair has keys **and** its fingerprint is in the
verified list. `pair_status()` returns `no-keys` | `untested` | `active`; `forms_mode()`
returns 'off' unless the pair it needs is active. `register()` hooks the front end only when
a forms mode is in force.

#### verify_pair() matrix

Reads **only** `bc_captcha_token` (our callbacks copy the provider token there).

| Condition | Result | Health |
|-----------|--------|--------|
| Pair not active | pass (no check) | — |
| Missing token | **closed** `captcha_missing` | failure if `bc_captcha_error` is an allowlisted client code |
| Token failing `is_plausible_token()` | **closed** `captcha_failed` | — |
| Transport error, non-2xx, unparseable body, empty `error-codes` | **open** `captcha_unavailable` + transient | — |
| Code in `$config_error_codes` (Turnstile `invalid-input-secret`, bad-request, …) | **open** `captcha_unavailable` + transient | — |
| `invalid-input-response`, `missing-input-response`, `timeout-or-duplicate` | **closed** `captcha_failed` | failure |
| Success, v3 score below threshold | **closed** `captcha_score:N` | success |
| Success | pass | success |

What "open" means is the caller's choice: forms and reset let the request through; the
login escape hatch falls back to the lockout.

#### Testing keys

`CaptchaKeyTest`: the admin page opens `admin-post.php?action=bc_captcha_probe` in an
iframe with the typed site key. The probe loads the provider script and posts
`{bcProbe, type: ready|size|token|error|timeout|script-blocked}` to the parent (checked
for origin, source and probe id). The token goes to `wp_ajax_bc_test_captcha` →
`CaptchaProvider::test_pair()` with the typed secret. Marked verified only on
`success === true`; refused for provider test keys (`hostname testkey.google.com`,
`metadata.result_with_testing_key`) and for the wrong key type (v2 must return no `score`,
v3 must). Transport problems are "inconclusive, nothing saved".

#### Health

`CaptchaHealth::failure()` stops writing after 10 per streak; `success()` writes only to end
a streak or refresh a timestamp older than 10 minutes. Warning after ≥5 failures and >1h
with no success. The verify path writes, never reads.

#### Elementor step-back

`ElementorCaptcha::form_has_own_captcha()` reads the form's saved definition
(`get_form_settings('form_fields')`) and requires both of Elementor's keys for that field
type. The front-end scripts mirror it via `client_skip_config()`.

### Admin page

Menu: "BlueCrocus Security" (dashicons-shield-alt), capability: `manage_options`
- **Settings tab**: spam protection, "CAPTCHA — Login & password reset", "CAPTCHA — Contact forms", password reset
- **Logs tab**: WP_List_Table with status filter, search, pagination (25/page), Clear Logs button

### Database

Table `wp_bc_form_logs` created via `dbDelta()`. Migration tracked by `bc_security_db_version` option. Runs on activation and at plugin-load time with a version check (`bc-security.php` calls it at file-include time, not on `plugins_loaded`). `CaptchaMigration::maybe_migrate()` runs right after it, also at include time — before the settings sanitizer is attached, so it writes raw values; the schema option is written last so an interrupted run reruns.

## Key decisions

- **Every enumeration vector gives one answer for real and made-up accounts** — a different answer for a real name (a 404 vs a redirect, "not registered" vs "wrong password", even a shake vs no shake) is the leak. Login errors are genericized at `authenticate` priority 40 (after BruteForce at 30), only when core's three enumeration codes are the whole error, so lockouts, the CAPTCHA check and other plugins' messages pass through. oEmbed keeps `author_name` (display name, already public on the post) and drops only `author_url`, because clients want author credit.
- **XML-RPC fully disabled** rather than rate-limited — it supports `system.multicall` which can batch hundreds of auth attempts in one request.
- **Transients for lockout state** — simpler, self-cleaning, no migration needed. Trade-off: not suitable for distributed setups without shared object cache.
- **IP detection checks X-Forwarded-For first** — needed behind reverse proxies (Cloudflare, nginx). The first IP in the chain is used. This is spoofable by the client; a trusted-proxy fix is tracked separately.
- **Hydra tests must use `S=` (success pattern)** — when lockout triggers, the response no longer contains the normal failure string, causing false positives with `F=` pattern.
- **IpResolver is injected** into BruteForce via constructor — allows testing with mock IPs and keeps IP logic separate from lockout logic.
- **Password reset uses its own transient prefix** (`bc_pwreset_ip_`, not `bc_lockout_`) — reset spam from a shared or NAT'd IP must never lock a legitimate client out of logging in. The two counters are independent on purpose.
- **The per-account cooldown is silent, the per-IP throttle is not** — returning "too many requests" for a specific account would confirm that account exists, reopening the enumeration oracle the generic response closes. A per-IP rate limit reveals nothing, so it can be overt.
- **Reset protection is per-account, not just per-IP** — IP-only limiting does nothing against a distributed botnet, which is the actual observed attack. The per-account cooldown is what stops a client's inbox filling up.
- **`lostpassword_errors` must handle two shapes** — core adds `invalid_email` *before* the filter and `invalidcombo` *after* it, so an unknown account arrives either with an error code already set or with an empty error bag and `$user_data === false`.
- **Google cannot tell a wrong key from a bot** — siteverify answers `invalid-input-response` for a forged token and for a genuine token checked against the wrong secret alike, and a wrong site key produces no token. So keys are enforced only after a real in-browser token passes (Test Keys), and the fingerprint includes the host so a staging push must be re-tested. Cloudflare does report a bad secret (`invalid-input-secret`).
- **CAPTCHA never gates ordinary sign-ins** — v3 had no way through for a real person scored low, and a broken key on the login form locks everyone out. The checkbox only replaces a lockout that would have happened anyway, and an unreachable provider falls back to that lockout.
- **The authenticate check runs at priority 30** — core's password check at 20 discards incoming errors, so an earlier priority could not stop anything.
- **Config faults fail open for forms and reset, bot verdicts fail closed** — blocking every visitor because a provider is down is worse than briefly losing the check, and the other layers still run. With Google a broken key is not a config fault (see above); `CaptchaHealth` is the only signal, and it only warns — a bot flood looks identical, so it must never loosen a check.
- **`bad-request` fails open, so tokens are shape-checked locally first** — it is the one config code a visitor could provoke by sending garbage, which would otherwise be a free CAPTCHA bypass. **If `is_plausible_token()` is ever loosened, move `bad-request` to the fail-closed list.**
- **`verify_pair()` reads only `bc_captcha_token`** — Elementor's `g-recaptcha-response`, CF7's field and Turnstile's own `cf-turnstile-response` can never be mistaken for ours.
- **Client error codes are allowlisted** — `bc_captcha_error` only feeds health tracking, so a bot spoofing it can at most raise a capped false warning, never pass a check.
- **CAPTCHA faults go to a transient + admin notice, not `bc_form_logs`** — a config fault is not a submission, and `LogsTable::column_status()` renders any non-`blocked` status as a green "Sent" badge, so it would display as a successful send. The transient is only rewritten when the payload changes, so a flood against a broken key cannot become one DB write per request.
- **`PasswordReset::check_captcha()` must `remove('invalid_email')` before adding `captcha_failed`** — core adds it before the hook; left in place WordPress prints "There is no account with that username or email address" beside the CAPTCHA error, handing the enumeration oracle back to any bot that simply omits the token.
- **Reset attempts are counted before the checkbox** — a bot that never sends a token must still burn its per-IP budget and hit the 429.
- **The CAPTCHA JS never holds a form for a library that isn't usable** — a blocked script once left forms permanently unsubmittable. The widget guard only blocks a submit when the widget actually rendered; v3 checks readiness at submit time. The server then decides.
- **Submit listeners run in the capture phase** — so they run before any form plugin's handler whatever order scripts loaded in.
- **The token is single-use and cleared after each submit** — all four form plugins submit by AJAX and stay on the page, so a retained token was replayed on the second submission and rejected as `timeout-or-duplicate`.
- **One CAPTCHA per form** — Elementor forms with their own configured reCAPTCHA are left to Elementor (Elementor's v3 handler submits via jQuery, so our script never sees a native submit). The decision comes from the saved form definition, never the request.
- **Blocked alphabets are on by default and strict** (owner's decision) — the client sites are English-language, and one Cyrillic, Chinese or Arabic letter blocks the submission. Strict also catches look-alike Cyrillic letters swapped into English words to dodge the keyword list. Each alphabet has its own tick box for a site that serves those customers; blocked messages stay readable in Logs.
- **Keywords match whole words, not substrings** — found anywhere in the text, `ico` blocked every Nicole and Mexico, `defi` every "definitely", `act now` every "contact now", in the name and email fields too. The cost: a keyword glued inside a longer word is no longer caught (`crypto` does not catch `cryptocurrency`, which is why the rollout adds it).
- **Deliberately not default keywords** — `web design`, `website design`, `outreach`, `outsourcing`, `proxies`: each blocks real enquiries on some client sites (agencies, charities, accountants, estate lawyers). Add them per site.
- **Contact-form CAPTCHA is off by default and switched off on upgrade** — the honeypot and keyword filter stop most form spam; CAPTCHA on forms is opt-in per site.

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
