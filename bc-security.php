<?php
/**
 * Plugin Name: BlueCrocus Security
 * Plugin URI:  https://bluecrocus.ca/
 * Description: WordPress security — brute force protection, user enumeration blocking, and form spam filtering with honeypot and keyword detection.
 * Version:     2.2.3
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

define( 'BC_SECURITY_VERSION', '2.2.3' );
define( 'BC_SECURITY_FILE', __FILE__ );
define( 'BC_MAX_ATTEMPTS', 5 );      // Failed attempts before lockout.
define( 'BC_LOCKOUT_SECONDS', 900 ); // Lockout duration: 15 minutes.

/* =========================================================================
 * Autoload & Bootstrap
 * ========================================================================= */

require __DIR__ . '/vendor/autoload.php';

// Database migration (lightweight version check).
( new BcSecurity\Database() )->maybe_create_tables();

// Security features.
$bc_captcha = new BcSecurity\CaptchaProvider();
$bc_captcha->register();

( new BcSecurity\BruteForce( new BcSecurity\IpResolver(), $bc_captcha ) )->register();
( new BcSecurity\UserEnumeration() )->register();
( new BcSecurity\UpdateChecker() )->register();

// Spam protection.
$bc_logger = new BcSecurity\FormLogger();
( new BcSecurity\SpamFilter( new BcSecurity\IpResolver(), $bc_logger, $bc_captcha ) )->register();

// Admin UI.
if ( is_admin() ) {
	( new BcSecurity\AdminPage( $bc_logger ) )->register();
}

// Run migration on plugin activation.
register_activation_hook( __FILE__, function () {
	( new BcSecurity\Database() )->maybe_create_tables();
} );
