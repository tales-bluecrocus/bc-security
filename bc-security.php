<?php
/**
 * Plugin Name: BlueCrocus Security
 * Plugin URI:  https://bluecrocus.ca/
 * Description: WordPress security — brute force protection, user enumeration blocking, and form spam filtering with honeypot and keyword detection.
 * Version:     2.4.0
 * Author:      Blue Crocus
 * Author URI:  https://bluecrocus.ca/
 * License:     GPL-2.0-or-later
 * Network:     true
 * Requires at least: 5.5
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

define( 'BC_SECURITY_VERSION', '2.4.0' );
define( 'BC_SECURITY_FILE', __FILE__ );
define( 'BC_MAX_ATTEMPTS', 5 );      // Failed attempts before lockout.
define( 'BC_LOCKOUT_SECONDS', 900 ); // Lockout duration: 15 minutes.

define( 'BC_RESET_MAX_ATTEMPTS', 3 );       // Reset requests per IP before throttling.
define( 'BC_RESET_WINDOW_SECONDS', 900 );   // Per-IP window and throttle duration: 15 minutes.
define( 'BC_RESET_COOLDOWN_SECONDS', 900 ); // Minimum gap between reset emails per account.

/* =========================================================================
 * Autoload & Bootstrap
 * ========================================================================= */

require __DIR__ . '/vendor/autoload.php';

// Database migration (lightweight version check).
( new BcSecurity\Database() )->maybe_create_tables();

// One-time move to the per-pair CAPTCHA settings of 2.3.
( new BcSecurity\CaptchaMigration() )->maybe_migrate();

// One-time addition of new default keywords to a saved keyword list.
( new BcSecurity\KeywordMigration() )->maybe_migrate();

// Security features.
$bc_elementor = new BcSecurity\ElementorCaptcha();
$bc_captcha   = new BcSecurity\CaptchaProvider(
	new BcSecurity\IpResolver(),
	new BcSecurity\CaptchaVerifiedKeys(),
	new BcSecurity\CaptchaHealth(),
	$bc_elementor
);
$bc_captcha->register();

( new BcSecurity\BruteForce( new BcSecurity\IpResolver(), $bc_captcha ) )->register();
( new BcSecurity\UserEnumeration() )->register();
( new BcSecurity\UpdateChecker() )->register();

// Spam protection.
$bc_logger = new BcSecurity\FormLogger();
( new BcSecurity\SpamFilter( new BcSecurity\IpResolver(), $bc_logger, $bc_captcha, $bc_elementor ) )->register();

// Password reset abuse protection.
( new BcSecurity\PasswordReset( new BcSecurity\IpResolver(), $bc_logger, $bc_captcha ) )->register();

// Admin UI.
if ( is_admin() ) {
	( new BcSecurity\AdminPage( $bc_logger, $bc_captcha, $bc_elementor ) )->register();
	( new BcSecurity\CaptchaKeyTest( $bc_captcha ) )->register();
}

// Run migration on plugin activation.
register_activation_hook( __FILE__, function () {
	( new BcSecurity\Database() )->maybe_create_tables();
} );
