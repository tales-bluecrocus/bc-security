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
