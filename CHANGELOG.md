# Changelog

All notable changes to BC Security will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-03-25

### Added
- PSR-4 class-based architecture under `BcSecurity\` namespace
- Composer autoload for dependency management
- Automatic plugin updates via GitHub Releases
- Release scripts for semantic versioning (`.config/bump-version.sh`)
- GitHub Actions CI/CD pipeline for automated builds

### Changed
- Plugin renamed from "PPC Security" to "BC Security"
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
