# BC Security — Spam Protection + Admin Page Design

## Goal

Add honeypot and keyword-based spam filtering for contact forms (Elementor Pro primary, CF7/Gravity/Formidable secondary), with a WordPress admin page for settings and submission logs.

## New Classes

| Class | Responsibility |
|-------|---------------|
| `Database` | Create/update `wp_bc_form_logs` table on activation |
| `FormLogger` | Insert/query log entries, provide data for admin page |
| `SpamFilter` | Honeypot injection + keyword validation across form plugins |
| `AdminPage` | Settings page with tabs (Settings + Logs), AJAX pagination |

## Database Table: `{prefix}bc_form_logs`

| Column | Type | Description |
|--------|------|-------------|
| `id` | BIGINT UNSIGNED AUTO_INCREMENT | Primary key |
| `created_at` | DATETIME | Submission timestamp (UTC) |
| `ip` | VARCHAR(45) | Client IP (IPv4 or IPv6) |
| `status` | VARCHAR(10) | `sent` or `blocked` |
| `block_reason` | VARCHAR(100) | NULL if sent; `honeypot` or `keyword:MATCHED_WORD` if blocked |
| `form_plugin` | VARCHAR(50) | `elementor`, `cf7`, `gravity`, `formidable` |
| `page_url` | VARCHAR(255) | URL where form was submitted |
| `form_data` | TEXT | JSON-encoded form fields (name, email, message) |

Index on `created_at` for log pagination. Index on `status` for filtering.

Migration runs on `register_activation_hook` and on `plugins_loaded` with a version check (stored in `wp_options` as `bc_security_db_version`).

## SpamFilter

### Honeypot

1. Injects a hidden field into forms via JavaScript (not server-side HTML, to avoid caching issues)
2. Field: `<input type="text" name="bc_hp_field" style="display:none !important" tabindex="-1" autocomplete="off" value="">`
3. On validation: if `bc_hp_field` is not empty → block with reason `honeypot`
4. Enabled/disabled via admin settings toggle (default: enabled)

### Keyword Filter

1. On the same validation hook, checks all text fields in the submission
2. Case-insensitive match against the blocked keywords list
3. Match → block with reason `keyword:MATCHED_WORD`
4. Keywords are stored in `wp_options` as `bc_security_settings`

### Default Keywords

```
seo, marketing, bitcoin, crypto, casino, viagra, forex, backlinks,
link building, guest post, cbd, diet pills, weight loss
```

### Hooks per Form Plugin

| Form Plugin | JS Injection Hook | Validation Hook | Success Hook |
|-------------|-------------------|-----------------|-------------|
| Elementor Pro | `elementor/frontend/after_enqueue_scripts` | `elementor_pro/forms/validation` | `elementor_pro/forms/new_record` |
| Contact Form 7 | `wpcf7_form_elements` | `wpcf7_before_send_mail` + `wpcf7_spam` | `wpcf7_mail_sent` |
| Gravity Forms | `gform_pre_render` | `gform_validation` | `gform_after_submission` |
| Formidable | `frm_entry_form` | `frm_validate_entry` | `frm_after_create_entry` |

**Validation flow:**

```
Form submitted
       │
       ▼
  Honeypot enabled? ──yes──> Field filled? ──yes──> BLOCK (honeypot)
       │                          │
      no                         no
       │                          │
       ▼                          ▼
  Check keywords ──match──> BLOCK (keyword:WORD)
       │
    no match
       │
       ▼
  ALLOW → log as 'sent'
```

Both blocked and sent submissions are logged via `FormLogger::log()`.

## FormLogger

```php
class FormLogger {
    public function log( array $data ): void;
    public function get_logs( array $args ): array;   // filterable: status, page, per_page, search
    public function get_total( array $args ): int;     // for pagination
    public function clear_logs(): void;                // delete all
}
```

### log() data structure

```php
[
    'ip'           => '1.2.3.4',
    'status'       => 'blocked',        // 'sent' or 'blocked'
    'block_reason' => 'keyword:bitcoin', // null if sent
    'form_plugin'  => 'elementor',
    'page_url'     => '/contact/',
    'form_data'    => ['name' => '...', 'email' => '...', 'message' => '...'],
]
```

`form_data` is JSON-encoded before insert. Sensitive fields (passwords) are never logged.

## AdminPage

### Menu

- Parent menu item: "BC Security" with dashicons `shield-alt`
- Capability required: `manage_options`
- Single page with two tabs

### Tab: Settings

- **Honeypot Protection**: Toggle switch (on/off), default on
- **Blocked Keywords**: Textarea, one keyword per line, pre-populated with defaults on first save
- **Save Settings** button
- Uses WordPress Settings API (`register_setting`, `add_settings_section`, `add_settings_field`)
- Nonce verification on save

### Tab: Logs

- **Filters row**: Status dropdown (All / Sent / Blocked) + text search (IP or keyword) + Filter button
- **Table**: Date, IP, Status (green "Sent" / red "Blocked" badge), Reason, Form Plugin, Page URL
- **Pagination**: 25 entries per page, standard WordPress pagination links
- **Clear Logs** button with JavaScript confirmation dialog
- Uses `WP_List_Table` for the logs table (standard WordPress admin pattern)
- Tab loads via query parameter `&tab=logs`, default tab is `settings`

### AJAX

Logs pagination and filtering use standard form GET parameters (not AJAX). This keeps it simple, compatible with `WP_List_Table`, and bookmarkable.

## Settings Storage

`wp_options` key: `bc_security_settings`

```php
[
    'honeypot_enabled' => true,
    'blocked_keywords' => ['seo', 'marketing', 'bitcoin', 'crypto', 'casino', 'viagra', 'forex', 'backlinks', 'link building', 'guest post', 'cbd', 'diet pills', 'weight loss'],
]
```

Default values are used when the option does not exist (first install).

## Bootstrap (bc-security.php)

```php
require __DIR__ . '/vendor/autoload.php';

// Database migration (lightweight version check).
( new BcSecurity\Database() )->maybe_create_tables();

// Security features.
( new BcSecurity\BruteForce( new BcSecurity\IpResolver() ) )->register();
( new BcSecurity\UserEnumeration() )->register();
( new BcSecurity\UpdateChecker() )->register();

// Spam protection.
$logger = new BcSecurity\FormLogger();
( new BcSecurity\SpamFilter( new BcSecurity\IpResolver(), $logger ) )->register();

// Admin UI.
if ( is_admin() ) {
    ( new BcSecurity\AdminPage( $logger ) )->register();
}
```

## File Structure (new files only)

```
src/
├── Database.php        # Table creation and migration
├── FormLogger.php      # Log insert/query/clear
├── SpamFilter.php      # Honeypot + keyword filter for all form plugins
├── AdminPage.php       # Settings + Logs tabs
└── LogsTable.php       # WP_List_Table subclass for logs display
```

## What Does NOT Change

- Existing brute force protection (BruteForce, IpResolver)
- User enumeration protection (UserEnumeration)
- Auto-update mechanism (UpdateChecker)
- Plugin constants and configuration pattern
