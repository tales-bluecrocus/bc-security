# BC Security — PSR-4 Refactor Design

## Goal

Refactor the single-file procedural plugin into a PSR-4 class-based architecture with all code and documentation in English.

## Structure

```
bc-security/
├── bc-security.php          # Bootstrap: plugin header, autoload, instantiation
├── composer.json             # PSR-4 autoload configuration
├── src/
│   ├── IpResolver.php        # Client IP detection
│   ├── BruteForce.php        # Login lockout system
│   └── UserEnumeration.php   # Block user discovery vectors
├── CLAUDE.md
└── README.md
```

## Namespace

`BcSecurity\` mapped to `src/` via Composer PSR-4 autoload.

```json
{
    "name": "bluecrocus/bc-security",
    "description": "WordPress security plugin — brute force protection and user enumeration blocking.",
    "type": "wordpress-plugin",
    "license": "GPL-2.0-or-later",
    "autoload": {
        "psr-4": {
            "BcSecurity\\": "src/"
        }
    },
    "require": {
        "php": ">=7.4"
    }
}
```

## Classes

### IpResolver

Responsible for detecting the real client IP behind proxies.

```php
namespace BcSecurity;

class IpResolver {
    public function getClientIp(): string;
}
```

- Checks `HTTP_X_FORWARDED_FOR`, `HTTP_X_REAL_IP`, `REMOTE_ADDR` in order.
- Returns first valid IP or `'0.0.0.0'` as fallback.
- Injected into `BruteForce` via constructor.

### BruteForce

Handles login rate limiting across all three authentication vectors.

```php
namespace BcSecurity;

class BruteForce {
    public function __construct( IpResolver $ip_resolver );
    public function register(): void;          // Hooks into WordPress
    private function transient_key( string $ip ): string;
    private function is_locked_out( string $ip ): int;    // Returns remaining seconds or 0
    private function record_failed_attempt( string $ip ): void;
    private function clear_attempts( string $ip ): void;
    private function send_lockout_response( int $remaining ): void;
    private function is_xmlrpc_request(): bool;
}
```

**Hooks registered by `register()`:**

| Hook | Type | Purpose |
|------|------|---------|
| `login_init` | action | Check lockout before wp-login POST |
| `wp_login_failed` | action | Record failed attempt |
| `wp_login` | action | Clear attempts on success |
| `xmlrpc_enabled` | filter | Disable XML-RPC |
| `xmlrpc_methods` | filter | Remove auth methods |
| `rest_pre_dispatch` (via `rest_api_init`) | filter | Check lockout on JWT endpoint |
| `jwt_auth_token_before_dispatch` | filter | Record JWT failures / clear on success |
| `authenticate` | filter | Shared lockout check |

### UserEnumeration

Blocks all user discovery vectors for unauthenticated visitors.

```php
namespace BcSecurity;

class UserEnumeration {
    public function register(): void;
}
```

**Hooks registered by `register()`:**

| Hook | Type | Purpose |
|------|------|---------|
| `rest_endpoints` | filter | Remove `/wp/v2/users` for unauthenticated |
| `template_redirect` | action | Redirect author archives to homepage |
| `parse_request` | action | Block `?author=N` enumeration |

## Bootstrap (bc-security.php)

```php
/**
 * Plugin Name: BC Security
 * ...
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'BC_MAX_ATTEMPTS', 5 );
define( 'BC_LOCKOUT_SECONDS', 900 );

require __DIR__ . '/vendor/autoload.php';

( new BcSecurity\BruteForce( new BcSecurity\IpResolver() ) )->register();
( new BcSecurity\UserEnumeration() )->register();
```

## Constants

| Old | New | Value |
|-----|-----|-------|
| `PPC_MAX_ATTEMPTS` | `BC_MAX_ATTEMPTS` | `5` |
| `PPC_LOCKOUT_SECONDS` | `BC_LOCKOUT_SECONDS` | `900` |

## What Changes

- Single file split into 3 classes + bootstrap
- All code and comments translated to English
- README rewritten in English
- CLAUDE.md updated to reflect new structure
- Function prefix `ppc_` replaced by class methods
- Constants prefix `PPC_` becomes `BC_`

## What Does NOT Change

- Business logic (5 attempts, 15min lockout, transients)
- WordPress hooks (same hooks, same priorities)
- Compatibility (JWT Auth, Cloudflare, Multisite)
- No new features, no new dependencies beyond Composer autoload
