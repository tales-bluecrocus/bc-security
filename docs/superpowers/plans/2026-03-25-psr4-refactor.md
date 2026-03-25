# PSR-4 Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the single-file procedural BC Security plugin into a PSR-4 class-based architecture with all code and documentation in English.

**Architecture:** Split `bc-security.php` into a lean bootstrap file plus three classes under `src/` (`IpResolver`, `BruteForce`, `UserEnumeration`) with `BcSecurity\` namespace. Composer handles autoloading. Each class has a `register()` method that hooks into WordPress.

**Tech Stack:** PHP 7.4+, WordPress 5.0+, Composer PSR-4 autoload

**Spec:** `docs/superpowers/specs/2026-03-25-psr4-refactor-design.md`

---

### Task 1: Create Composer config and autoload

**Files:**
- Create: `composer.json`
- Create: `src/` (directory)

- [ ] **Step 1: Create composer.json**

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

- [ ] **Step 2: Create src/ directory**

```bash
mkdir -p src
```

- [ ] **Step 3: Generate autoload files**

```bash
composer dump-autoload
```

Expected: `vendor/autoload.php` created, no errors.

- [ ] **Step 4: Add vendor/ to .gitignore**

Create `.gitignore`:

```
/vendor/
```

- [ ] **Step 5: Commit**

```bash
git add composer.json .gitignore src/
git commit -m "feat: add Composer PSR-4 autoload config"
```

---

### Task 2: Create IpResolver class

**Files:**
- Create: `src/IpResolver.php`

- [ ] **Step 1: Create src/IpResolver.php**

```php
<?php
/**
 * Resolves the real client IP address behind proxies.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class IpResolver {

	/**
	 * Get the client IP address.
	 *
	 * Checks proxy headers first (X-Forwarded-For, X-Real-IP),
	 * then falls back to REMOTE_ADDR.
	 *
	 * @return string Valid IP address or '0.0.0.0' as fallback.
	 */
	public function get_client_ip(): string {
		$headers = array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' );

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip = explode( ',', $_SERVER[ $header ] )[0];
				$ip = trim( $ip );

				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		return '0.0.0.0';
	}
}
```

- [ ] **Step 2: Verify autoload resolves the class**

```bash
composer dump-autoload
php -r "require 'vendor/autoload.php'; new BcSecurity\IpResolver();" && echo "OK"
```

Expected: `OK`, no errors.

- [ ] **Step 3: Commit**

```bash
git add src/IpResolver.php
git commit -m "feat: add IpResolver class for client IP detection"
```

---

### Task 3: Create BruteForce class

**Files:**
- Create: `src/BruteForce.php`

- [ ] **Step 1: Create src/BruteForce.php**

```php
<?php
/**
 * Brute force protection — rate-limits login attempts across all authentication vectors.
 *
 * Covers wp-login.php, XML-RPC (disabled entirely), and JWT Auth endpoints.
 * Uses WordPress transients for lockout state per IP.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class BruteForce {

	/**
	 * @var IpResolver
	 */
	private $ip_resolver;

	/**
	 * @param IpResolver $ip_resolver IP detection dependency.
	 */
	public function __construct( IpResolver $ip_resolver ) {
		$this->ip_resolver = $ip_resolver;
	}

	/**
	 * Register all WordPress hooks for brute force protection.
	 */
	public function register(): void {
		// Vector A: wp-login.php
		add_action( 'login_init', array( $this, 'check_lockout_on_login' ) );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ) );
		add_action( 'wp_login', array( $this, 'on_login_success' ) );

		// Vector B: XML-RPC — disabled entirely
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'xmlrpc_methods', array( $this, 'remove_xmlrpc_auth_methods' ) );

		// Vector C: JWT Auth endpoint
		add_action( 'rest_api_init', array( $this, 'register_rest_hooks' ) );
		add_filter( 'jwt_auth_token_before_dispatch', array( $this, 'on_jwt_auth_result' ), 10, 2 );

		// Shared: authenticate filter covers wp-login + JWT
		add_filter( 'authenticate', array( $this, 'check_lockout_on_authenticate' ), 30, 3 );
	}

	/**
	 * Block locked-out IPs before wp-login.php processes the POST.
	 */
	public function check_lockout_on_login(): void {
		if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
			return;
		}

		$ip        = $this->ip_resolver->get_client_ip();
		$remaining = $this->is_locked_out( $ip );

		if ( $remaining > 0 ) {
			$this->send_lockout_response( $remaining );
		}
	}

	/**
	 * Record a failed login attempt.
	 */
	public function on_login_failed(): void {
		$this->record_failed_attempt( $this->ip_resolver->get_client_ip() );
	}

	/**
	 * Clear failed attempts on successful login.
	 */
	public function on_login_success(): void {
		$this->clear_attempts( $this->ip_resolver->get_client_ip() );
	}

	/**
	 * Remove authentication-related XML-RPC methods.
	 *
	 * @param array $methods XML-RPC methods.
	 * @return array Filtered methods.
	 */
	public function remove_xmlrpc_auth_methods( array $methods ): array {
		unset( $methods['wp.getUsersBlogs'] );
		unset( $methods['wp.getAuthors'] );
		unset( $methods['wp.getUsers'] );

		return $methods;
	}

	/**
	 * Register REST API hooks for JWT lockout checking.
	 */
	public function register_rest_hooks(): void {
		add_filter( 'rest_pre_dispatch', array( $this, 'check_lockout_on_jwt' ), 10, 3 );
	}

	/**
	 * Check lockout on JWT token endpoint.
	 *
	 * @param mixed            $result  Response to replace the requested one.
	 * @param \WP_REST_Server  $server  REST server instance.
	 * @param \WP_REST_Request $request REST request.
	 * @return mixed|\WP_Error Original result or lockout error.
	 */
	public function check_lockout_on_jwt( $result, $server, $request ) {
		if ( $request->get_route() !== '/jwt-auth/v1/token' || $request->get_method() !== 'POST' ) {
			return $result;
		}

		$ip        = $this->ip_resolver->get_client_ip();
		$remaining = $this->is_locked_out( $ip );

		if ( $remaining > 0 ) {
			return new \WP_Error(
				'too_many_requests',
				'Too many failed login attempts. Try again in ' . ceil( $remaining / 60 ) . ' minute(s).',
				array( 'status' => 429 )
			);
		}

		return $result;
	}

	/**
	 * Handle JWT authentication result — record failure or clear on success.
	 *
	 * @param mixed $response JWT response data.
	 * @param mixed $user     WP_User on success, WP_Error on failure.
	 * @return mixed Unmodified response.
	 */
	public function on_jwt_auth_result( $response, $user ) {
		if ( is_wp_error( $user ) ) {
			$this->record_failed_attempt( $this->ip_resolver->get_client_ip() );
		} else {
			$this->clear_attempts( $this->ip_resolver->get_client_ip() );
		}

		return $response;
	}

	/**
	 * Check lockout during the authenticate filter (covers wp-login + JWT).
	 *
	 * @param mixed  $user     Null, WP_User, or WP_Error.
	 * @param string $username Provided username.
	 * @param string $password Provided password.
	 * @return mixed|\WP_Error Original value or lockout error.
	 */
	public function check_lockout_on_authenticate( $user, $username, $password ) {
		if ( empty( $username ) || empty( $password ) ) {
			return $user;
		}

		$ip        = $this->ip_resolver->get_client_ip();
		$remaining = $this->is_locked_out( $ip );

		if ( $remaining > 0 ) {
			return new \WP_Error(
				'too_many_requests',
				'Too many failed login attempts. Try again in ' . ceil( $remaining / 60 ) . ' minute(s).'
			);
		}

		return $user;
	}

	/**
	 * Get the transient key for a given IP.
	 *
	 * @param string $ip Client IP address.
	 * @return string Transient key.
	 */
	private function transient_key( string $ip ): string {
		return 'bc_lockout_' . md5( $ip );
	}

	/**
	 * Check if an IP is currently locked out.
	 *
	 * @param string $ip Client IP address.
	 * @return int Remaining lockout seconds, or 0 if not locked out.
	 */
	private function is_locked_out( string $ip ): int {
		$data = get_transient( $this->transient_key( $ip ) );

		if ( ! is_array( $data ) ) {
			return 0;
		}

		if ( $data['attempts'] >= BC_MAX_ATTEMPTS ) {
			return max( 0, $data['locked_until'] - time() );
		}

		return 0;
	}

	/**
	 * Record a failed login attempt for an IP.
	 *
	 * @param string $ip Client IP address.
	 */
	private function record_failed_attempt( string $ip ): void {
		$key  = $this->transient_key( $ip );
		$data = get_transient( $key );

		if ( ! is_array( $data ) ) {
			$data = array( 'attempts' => 0, 'locked_until' => 0 );
		}

		$data['attempts']++;

		if ( $data['attempts'] >= BC_MAX_ATTEMPTS ) {
			$data['locked_until'] = time() + BC_LOCKOUT_SECONDS;
		}

		set_transient( $key, $data, BC_LOCKOUT_SECONDS );
	}

	/**
	 * Clear failed attempts for an IP.
	 *
	 * @param string $ip Client IP address.
	 */
	private function clear_attempts( string $ip ): void {
		delete_transient( $this->transient_key( $ip ) );
	}

	/**
	 * Send a locked-out HTTP response and terminate.
	 *
	 * @param int $remaining Seconds remaining in lockout.
	 */
	private function send_lockout_response( int $remaining ): void {
		$minutes = (int) ceil( $remaining / 60 );

		if ( wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || $this->is_xmlrpc_request() ) {
			status_header( 429 );
			header( 'Content-Type: application/json; charset=utf-8' );
			header( "Retry-After: $remaining" );
			wp_die(
				wp_json_encode( array(
					'code'    => 'too_many_requests',
					'message' => "Too many failed login attempts. Try again in {$minutes} minute(s).",
					'data'    => array( 'status' => 429 ),
				) ),
				'Too Many Requests',
				array( 'response' => 429 )
			);
		}

		// HTML response for wp-login.php.
		status_header( 429 );
		header( "Retry-After: $remaining" );
		wp_die(
			"<h1>Access Denied</h1><p>Too many failed login attempts. Try again in {$minutes} minute(s).</p>",
			'Too Many Requests',
			array( 'response' => 429 )
		);
	}

	/**
	 * Check if the current request is an XML-RPC request.
	 *
	 * @return bool
	 */
	private function is_xmlrpc_request(): bool {
		return defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST;
	}
}
```

- [ ] **Step 2: Verify autoload resolves the class**

```bash
composer dump-autoload
php -r "require 'vendor/autoload.php'; new BcSecurity\BruteForce(new BcSecurity\IpResolver());" && echo "OK"
```

Expected: `OK`, no errors.

- [ ] **Step 3: Commit**

```bash
git add src/BruteForce.php
git commit -m "feat: add BruteForce class for login rate limiting"
```

---

### Task 4: Create UserEnumeration class

**Files:**
- Create: `src/UserEnumeration.php`

- [ ] **Step 1: Create src/UserEnumeration.php**

```php
<?php
/**
 * User enumeration protection — blocks discovery of valid usernames.
 *
 * Covers REST API /wp/v2/users, author archives, and ?author=N query parameter.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class UserEnumeration {

	/**
	 * Register all WordPress hooks for user enumeration protection.
	 */
	public function register(): void {
		add_filter( 'rest_endpoints', array( $this, 'remove_users_endpoint' ) );
		add_action( 'template_redirect', array( $this, 'redirect_author_archives' ) );
		add_action( 'parse_request', array( $this, 'block_author_query' ) );
	}

	/**
	 * Remove /wp/v2/users endpoints for unauthenticated requests.
	 *
	 * @param array $endpoints Registered REST endpoints.
	 * @return array Filtered endpoints.
	 */
	public function remove_users_endpoint( array $endpoints ): array {
		if ( ! is_user_logged_in() ) {
			unset( $endpoints['/wp/v2/users'] );
			unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		}

		return $endpoints;
	}

	/**
	 * Redirect author archive requests to the homepage.
	 */
	public function redirect_author_archives(): void {
		if ( is_author() ) {
			wp_redirect( home_url(), 301 );
			exit;
		}
	}

	/**
	 * Block ?author=N enumeration before the query runs.
	 *
	 * @param \WP $wp WordPress request object.
	 */
	public function block_author_query( \WP $wp ): void {
		if ( ! is_admin() && isset( $wp->query_vars['author'] ) && ! is_user_logged_in() ) {
			wp_redirect( home_url(), 301 );
			exit;
		}
	}
}
```

- [ ] **Step 2: Verify autoload resolves the class**

```bash
php -r "require 'vendor/autoload.php'; new BcSecurity\UserEnumeration();" && echo "OK"
```

Expected: `OK`, no errors.

- [ ] **Step 3: Commit**

```bash
git add src/UserEnumeration.php
git commit -m "feat: add UserEnumeration class for user discovery protection"
```

---

### Task 5: Rewrite bootstrap file (bc-security.php)

**Files:**
- Modify: `bc-security.php` (full rewrite)

- [ ] **Step 1: Rewrite bc-security.php**

```php
<?php
/**
 * Plugin Name: BC Security
 * Plugin URI:  https://bluecrocus.ca/
 * Description: WordPress security — blocks user enumeration and brute force attacks (wp-login, XML-RPC, JWT) with IP-based lockout.
 * Version:     2.0.0
 * Author:      Blue Crocus
 * Author URI:  https://bluecrocus.ca/
 * License:     GPL-2.0-or-later
 * Network:     true
 * Requires at least: 5.0
 * Requires PHP: 7.4
 *
 * @package BcSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/* =========================================================================
 * Configuration
 * ========================================================================= */

define( 'BC_MAX_ATTEMPTS', 5 );      // Failed attempts before lockout.
define( 'BC_LOCKOUT_SECONDS', 900 ); // Lockout duration: 15 minutes.

/* =========================================================================
 * Autoload & Bootstrap
 * ========================================================================= */

require __DIR__ . '/vendor/autoload.php';

( new BcSecurity\BruteForce( new BcSecurity\IpResolver() ) )->register();
( new BcSecurity\UserEnumeration() )->register();
```

- [ ] **Step 2: Verify PHP syntax**

```bash
php -l bc-security.php
```

Expected: `No syntax errors detected`

- [ ] **Step 3: Commit**

```bash
git add bc-security.php
git commit -m "refactor: rewrite bootstrap to use PSR-4 classes"
```

---

### Task 6: Rewrite README.md in English

**Files:**
- Modify: `README.md` (full rewrite)

- [ ] **Step 1: Rewrite README.md**

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README in English with updated architecture"
```

---

### Task 7: Update CLAUDE.md for new structure

**Files:**
- Modify: `CLAUDE.md` (full rewrite)

- [ ] **Step 1: Rewrite CLAUDE.md**

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for PSR-4 architecture"
```

---

### Task 8: Final verification

- [ ] **Step 1: Verify complete file structure**

```bash
find . -type f -not -path './vendor/*' -not -path './.git/*' | sort
```

Expected output:
```
./CLAUDE.md
./README.md
./bc-security.php
./composer.json
./.gitignore
./src/BruteForce.php
./src/IpResolver.php
./src/UserEnumeration.php
```

- [ ] **Step 2: Verify all classes autoload correctly**

```bash
php -r "
require 'vendor/autoload.php';
\$ip = new BcSecurity\IpResolver();
echo 'IpResolver: OK' . PHP_EOL;
\$bf = new BcSecurity\BruteForce(\$ip);
echo 'BruteForce: OK' . PHP_EOL;
\$ue = new BcSecurity\UserEnumeration();
echo 'UserEnumeration: OK' . PHP_EOL;
"
```

Expected:
```
IpResolver: OK
BruteForce: OK
UserEnumeration: OK
```

- [ ] **Step 3: Verify no PHP syntax errors in any file**

```bash
php -l bc-security.php && php -l src/IpResolver.php && php -l src/BruteForce.php && php -l src/UserEnumeration.php
```

Expected: `No syntax errors detected` for each file.

- [ ] **Step 4: Verify no Portuguese remains in source files**

```bash
grep -riP '[àáâãéêíóôõúç]' bc-security.php src/ || echo "No Portuguese found"
```

Expected: `No Portuguese found`

- [ ] **Step 5: Commit any remaining changes and tag release**

```bash
git status
# If clean, no commit needed. Otherwise:
# git add -A && git commit -m "chore: final cleanup"
```
