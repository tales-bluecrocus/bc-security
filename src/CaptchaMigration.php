<?php
/**
 * One-time move from the single-provider CAPTCHA settings of 2.2/2.3 to the
 * per-pair settings of 2.4.
 *
 * Nothing it writes can block a visitor: every surface also needs its pair to pass
 * Test Keys on this host, and the verified list starts empty. So even a migration
 * that failed half-way leaves CAPTCHA off, with the rate limits, honeypot and
 * keyword filter still protecting the site.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class CaptchaMigration {

	/**
	 * Option recording the CAPTCHA settings schema in use.
	 */
	const SCHEMA_OPTION = 'bc_security_captcha_schema';

	/**
	 * Option holding what the old settings said, for the one-time notice.
	 */
	const LEGACY_OPTION = 'bc_security_captcha_legacy';

	/**
	 * Current schema.
	 */
	const SCHEMA = 2;

	/**
	 * Migrate once. Runs at plugin load, before the settings sanitizer is attached,
	 * so it writes raw values. The schema marker is written last: a run interrupted
	 * part-way simply runs again.
	 */
	public function maybe_migrate(): void {
		if ( (int) get_option( self::SCHEMA_OPTION, 0 ) >= self::SCHEMA ) {
			return;
		}

		$settings = get_option( CaptchaSettings::OPTION, null );

		if ( is_array( $settings ) && ! array_key_exists( 'captcha_forms_mode', $settings ) ) {
			$old_provider = isset( $settings['captcha_provider'] ) ? (string) $settings['captcha_provider'] : 'off';
			$old_site     = isset( $settings['captcha_site_key'] ) ? (string) $settings['captcha_site_key'] : '';
			$old_secret   = isset( $settings['captcha_secret_key'] ) ? (string) $settings['captcha_secret_key'] : '';

			// add_option() never overwrites, so a second run cannot clobber it.
			add_option( self::LEGACY_OPTION, array(
				'provider'         => $old_provider,
				'on_login'         => ! empty( $settings['captcha_on_login'] ),
				'on_lostpassword'  => ! empty( $settings['captcha_on_lostpassword'] ),
				'migrated_at'      => time(),
				'notice_dismissed' => false,
			), '', 'no' );

			// Contact-form CAPTCHA starts off everywhere (owner's decision); before
			// 2.4 it switched on automatically for every form once keys were saved.
			$settings['captcha_forms_mode']      = 'off';
			$settings['captcha_login_challenge'] = true;

			// Turnstile keys still fit the main slot, and stay inactive until tested.
			// reCAPTCHA v3 keys cannot draw a v2 checkbox, so they move to the
			// contact-form Invisible slot, also inactive.
			if ( 'turnstile' === $old_provider ) {
				$settings['captcha_main_provider']   = 'turnstile';
				$settings['captcha_main_site_key']   = $old_site;
				$settings['captcha_main_secret_key'] = $old_secret;
			} else {
				$settings['captcha_main_provider']   = 'recaptcha_v2';
				$settings['captcha_main_site_key']   = '';
				$settings['captcha_main_secret_key'] = '';
			}

			$settings['captcha_v3_site_key']   = 'recaptcha_v3' === $old_provider ? $old_site : '';
			$settings['captcha_v3_secret_key'] = 'recaptcha_v3' === $old_provider ? $old_secret : '';

			// The old keys are left in place, so a manual downgrade still works. The
			// settings sanitizer drops them on the next save.
			update_option( CaptchaSettings::OPTION, $settings );
		}

		update_option( self::SCHEMA_OPTION, self::SCHEMA, true );
	}
}
