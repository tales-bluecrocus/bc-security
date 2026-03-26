# Changelog

All notable changes to BlueCrocus Security will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.2.0] - 2026-03-26

### Added
- Optional CAPTCHA protection with reCAPTCHA v3 and Cloudflare Turnstile support
- CAPTCHA settings section in admin page (provider, site key, secret key, score threshold, login toggle)
- CAPTCHA verification as first layer before honeypot and keyword checks
- Login page CAPTCHA protection (optional, disabled by default)
- Fail-open behavior: forms still work if CAPTCHA API is unavailable
- Immediate blocking of login attempts with non-existent usernames (counters distributed brute force attacks that rotate IPs)

## [2.1.1] - 2026-03-25

### Changed
- Expanded default blocked keywords from 13 to 140+ patterns across 7 categories: SEO & Digital Marketing, Crypto & Bitcoin, Sales & Cold Outreach, Cheap Dev & Design, Financial Scams, Common Spam Patterns, and General

## [2.1.0] - 2026-03-25

### Added
- Form spam protection with honeypot field and keyword filtering
- Support for Elementor Pro, Contact Form 7, Gravity Forms, and Formidable Forms
- Admin page (Settings > BlueCrocus Security) with two tabs
- Settings tab: honeypot toggle and configurable blocked keywords list
- Logs tab: form submission log with status filter, search, and pagination
- Custom database table (`wp_bc_form_logs`) for submission logging
- Default blocked keywords: seo, marketing, bitcoin, crypto, casino, viagra, forex, backlinks, etc.

### Changed
- Plugin renamed to "BlueCrocus Security"

## [2.0.1] - 2026-03-25

### Added
- CHANGELOG.md with full release history
- Changelog validation check in release script

## [2.0.0] - 2026-03-25

### Added
- PSR-4 class-based architecture under `BcSecurity\` namespace
- Composer autoload for dependency management
- Automatic plugin updates via GitHub Releases
- Release scripts for semantic versioning (`.config/bump-version.sh`)
- GitHub Actions CI/CD pipeline for automated builds

### Changed
- Plugin renamed from "PPC Security" to "BlueCrocus Security"
- All code and documentation translated to English
- Constants renamed from `PPC_*` to `BC_*`
- Transient keys renamed from `ppc_lockout_` to `bc_lockout_`

## [1.1.0] - 2026-03-24

### Added
- Brute force protection across all 3 authentication vectors (wp-login, XML-RPC, JWT)
- IP-based rate limiting — 5 failed attempts triggers 15-minute lockout
- XML-RPC authentication fully disabled (blocks `system.multicall` abuse)
- HTTP 429 response with `Retry-After` header for locked-out IPs
- Shared lockout counter between wp-login.php and JWT Auth endpoints

## [1.0.0] - 2026-03-23

### Added
- User enumeration protection for REST API (`/wp/v2/users` removed for unauthenticated requests)
- Author archive redirect (301 to homepage)
- Query parameter `?author=N` blocking (301 to homepage)
