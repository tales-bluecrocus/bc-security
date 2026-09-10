<?php
/**
 * Detects other active plugins that also serve a CAPTCHA.
 *
 * Two CAPTCHA scripts on one page is the classic cause of "the form does nothing
 * when I click send": both bind submit handlers, and whichever loses the race
 * submits without the other's token. Running two also doubles the monthly quota
 * consumed and doubles the chances of a real visitor being wrongly blocked,
 * without catching meaningfully more bots.
 *
 * This class only reports. It never blocks saving and never disables anything.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class CaptchaConflicts {

	/**
	 * Plugins whose CAPTCHA keys live in a plain option.
	 *
	 * Detection is additive, so an option name that turns out to be wrong causes a
	 * missed detection, never a false positive.
	 *
	 * @var array
	 */
	private static $key_options = array(
		'Elementor Pro'                          => array(
			'elementor_pro_recaptcha_site_key',
			'elementor_pro_recaptcha_v3_site_key',
		),
		'Contact Form 7'                         => array( 'wpcf7_recaptcha_sitekey' ),
		'Simple Cloudflare Turnstile'            => array( 'cfturnstile_key' ),
		'Advanced noCaptcha & Invisible Captcha' => array( 'anr_site_key' ),
	);

	/**
	 * Plugins that can provide a CAPTCHA but whose configuration is not cheaply
	 * readable from here.
	 *
	 * Runtime signals rather than is_plugin_active(): defined() and class_exists()
	 * survive renamed plugin folders and mu-plugin installs, and need no extra
	 * include. is_plugin_active() requires wp-admin/includes/plugin.php, which is
	 * not guaranteed to be loaded on every screen where admin_notices fires.
	 *
	 * @var array
	 */
	private static $runtime_signals = array(
		'Wordfence'      => array( 'constant' => 'WORDFENCE_VERSION', 'class' => '' ),
		'Solid Security' => array( 'constant' => '', 'class' => 'ITSEC_Core' ),
	);

	/**
	 * Detect other CAPTCHA providers on this site.
	 *
	 * @return array Array with 'configured' (plugins with CAPTCHA keys actually set)
	 *               and 'possible' (active plugins that can provide a CAPTCHA).
	 */
	public function detect(): array {
		$configured = array();
		$possible   = array();

		foreach ( self::$key_options as $label => $options ) {
			foreach ( $options as $option ) {
				if ( ! empty( get_option( $option, '' ) ) ) {
					$configured[] = $label;
					break;
				}
			}
		}

		// WPForms nests its keys inside a settings array.
		$wpforms = get_option( 'wpforms_settings', array() );
		if ( is_array( $wpforms ) && ! empty( $wpforms['recaptcha-site-key'] ) ) {
			$configured[] = 'WPForms';
		}

		// Solid Security / iThemes Security stores module config in itsec-storage.
		$itsec = get_option( 'itsec-storage', array() );
		if ( is_array( $itsec ) ) {
			foreach ( array( 'recaptcha', 'google-recaptcha', 'captcha' ) as $module ) {
				if ( ! empty( $itsec[ $module ]['site_key'] ) || ! empty( $itsec[ $module ]['sitekey'] ) ) {
					$configured[] = 'Solid Security';
					break;
				}
			}
		}

		foreach ( self::$runtime_signals as $label => $signal ) {
			if ( in_array( $label, $configured, true ) ) {
				continue;
			}

			$found = ( $signal['constant'] && defined( $signal['constant'] ) )
				|| ( $signal['class'] && class_exists( $signal['class'] ) );

			if ( $found ) {
				$possible[] = $label;
			}
		}

		return array(
			'configured' => array_values( array_unique( $configured ) ),
			'possible'   => array_values( array_unique( $possible ) ),
		);
	}
}
