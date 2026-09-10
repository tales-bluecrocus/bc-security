<?php
/**
 * CAPTCHA settings — the single source of defaults and key pairs.
 *
 * Two key pairs, because Google issues v2 and v3 keys separately (a key is one type
 * or the other):
 *   - 'main': reCAPTCHA v2 checkbox or Cloudflare Turnstile. Used by the login
 *     escape hatch, the lost-password form, and contact forms in Checkbox mode.
 *   - 'v3':   reCAPTCHA v3, used only by contact forms in Invisible mode.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class CaptchaSettings {

	/**
	 * Option holding every plugin setting.
	 */
	const OPTION = 'bc_security_settings';

	/**
	 * Providers allowed for the main pair.
	 */
	const MAIN_PROVIDERS = array( 'recaptcha_v2', 'turnstile' );

	/**
	 * Contact-form CAPTCHA modes.
	 */
	const FORM_MODES = array( 'off', 'checkbox', 'v3' );

	/**
	 * Revision marker rendered into the settings form.
	 *
	 * A save without it came from a settings page opened before this version was
	 * installed, and must not wipe the CAPTCHA values it knows nothing about.
	 */
	const FORM_REVISION = '2';

	/**
	 * CAPTCHA defaults.
	 *
	 * @return array
	 */
	public static function defaults(): array {
		return array(
			'captcha_main_provider'   => 'recaptcha_v2',
			'captcha_main_site_key'   => '',
			'captcha_main_secret_key' => '',
			'captcha_login_challenge' => true,
			'captcha_on_lostpassword' => false,
			'captcha_forms_mode'      => 'off',
			'captcha_v3_site_key'     => '',
			'captcha_v3_secret_key'   => '',
			'captcha_score_threshold' => 0.5,
		);
	}

	/**
	 * All settings, with CAPTCHA defaults filled in.
	 *
	 * @return array
	 */
	public static function get(): array {
		$settings = get_option( self::OPTION, array() );

		return wp_parse_args( is_array( $settings ) ? $settings : array(), self::defaults() );
	}

	/**
	 * The provider and keys for one pair.
	 *
	 * @param string $pair 'main' or 'v3'.
	 * @return array Array with 'provider', 'site' and 'secret'.
	 */
	public static function pair( string $pair ): array {
		$settings = self::get();

		if ( 'v3' === $pair ) {
			return array(
				'provider' => 'recaptcha_v3',
				'site'     => (string) $settings['captcha_v3_site_key'],
				'secret'   => (string) $settings['captcha_v3_secret_key'],
			);
		}

		$provider = in_array( $settings['captcha_main_provider'], self::MAIN_PROVIDERS, true )
			? $settings['captcha_main_provider']
			: 'recaptcha_v2';

		return array(
			'provider' => $provider,
			'site'     => (string) $settings['captcha_main_site_key'],
			'secret'   => (string) $settings['captcha_main_secret_key'],
		);
	}

	/**
	 * Normalise a pasted key: text only, no whitespace anywhere.
	 *
	 * Keys copied from a console often pick up a trailing space or line break,
	 * which would otherwise make a correct key fail its test.
	 *
	 * @param mixed $value Raw value.
	 * @return string
	 */
	public static function clean_key( $value ): string {
		return (string) preg_replace( '/\s+/', '', sanitize_text_field( (string) $value ) );
	}

	/**
	 * This site's host name, lower-cased.
	 *
	 * @return string
	 */
	public static function home_host(): string {
		return strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
	}

	/**
	 * Fingerprint of a key pair on this host.
	 *
	 * The host is included because reCAPTCHA keys are registered to domains: a
	 * staging site pushed to production must be tested again before it enforces.
	 * Only this hash is ever stored, never a second copy of the secret.
	 *
	 * @param string $pair     'main' or 'v3'.
	 * @param string $provider Provider slug.
	 * @param string $site     Site key.
	 * @param string $secret   Secret key.
	 * @return string
	 */
	public static function fingerprint( string $pair, string $provider, string $site, string $secret ): string {
		return hash( 'sha256', implode( "\n", array( self::home_host(), $pair, $provider, $site, $secret ) ) );
	}

	/**
	 * Human-readable provider name.
	 *
	 * @param string $provider Provider slug.
	 * @return string
	 */
	public static function provider_label( string $provider ): string {
		switch ( $provider ) {
			case 'turnstile':
				return 'Cloudflare Turnstile';
			case 'recaptcha_v3':
				return 'Google reCAPTCHA v3';
			default:
				return 'Google reCAPTCHA v2';
		}
	}
}
