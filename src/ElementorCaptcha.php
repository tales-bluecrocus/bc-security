<?php
/**
 * Detects Elementor Pro forms that carry their own working reCAPTCHA.
 *
 * One CAPTCHA per form. When a form already has Elementor's reCAPTCHA field and
 * Elementor's keys for that field type are saved, Elementor verifies it server-side
 * itself, so BC Security steps back on that form: its honeypot and keyword checks
 * still run, its CAPTCHA does not.
 *
 * For v3 this is not an optimisation, it is the only thing that works. Elementor's
 * v3 handler cancels the submit button's click and submits the form through jQuery,
 * so the browser never fires a native submit event, our script never attaches a
 * token, and every submission would fail as captcha_missing. For v2 it avoids
 * checking every visitor twice and a second set of keys that could break the form.
 *
 * The decision comes from the form's saved definition and Elementor's saved
 * options, never from the submitted request — a bot must not be able to add a
 * field to switch our check off.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class ElementorCaptcha {

	/**
	 * Elementor reCAPTCHA field types and the options holding their keys.
	 *
	 * Field types confirmed from Elementor Pro's editor script. The site-key option
	 * names are confirmed by the conflict warning firing in testing; the secret-key
	 * names follow the same pattern. A wrong name here means we never step back,
	 * which reproduces today's behaviour rather than removing protection.
	 *
	 * @var array
	 */
	private static $types = array(
		'recaptcha'    => array(
			'site'   => 'elementor_pro_recaptcha_site_key',
			'secret' => 'elementor_pro_recaptcha_secret_key',
		),
		'recaptcha_v3' => array(
			'site'   => 'elementor_pro_recaptcha_v3_site_key',
			'secret' => 'elementor_pro_recaptcha_v3_secret_key',
		),
	);

	/**
	 * Check whether Elementor has both keys saved for a reCAPTCHA field type.
	 *
	 * Both are required: with only a site key Elementor renders the widget but does
	 * not verify it server-side, so stepping back would leave the form unprotected.
	 *
	 * @param string $type Elementor field type ('recaptcha' or 'recaptcha_v3').
	 * @return bool
	 */
	public function is_configured( string $type ): bool {
		if ( ! isset( self::$types[ $type ] ) ) {
			return false;
		}

		$site   = trim( (string) get_option( self::$types[ $type ]['site'], '' ) );
		$secret = trim( (string) get_option( self::$types[ $type ]['secret'], '' ) );

		return '' !== $site && '' !== $secret;
	}

	/**
	 * Check whether a submitted Elementor form carries its own working reCAPTCHA.
	 *
	 * @param object $record Elementor Pro form record.
	 * @return bool
	 */
	public function form_has_own_captcha( $record ): bool {
		foreach ( $this->field_types( $record ) as $type ) {
			if ( $this->is_configured( $type ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Flags telling the front-end script which Elementor reCAPTCHA types to leave alone.
	 *
	 * Must mirror form_has_own_captcha(): if the script skipped a form the server then
	 * checked, the form would arrive without our token and be blocked.
	 *
	 * @return array Array with 'v2' and 'v3' booleans.
	 */
	public function client_skip_config(): array {
		return array(
			'v2' => $this->is_configured( 'recaptcha' ),
			'v3' => $this->is_configured( 'recaptcha_v3' ),
		);
	}

	/**
	 * Collect the field types defined on a form.
	 *
	 * Reads the saved form definition first. The processed record fields are only a
	 * fallback, because Elementor's own reCAPTCHA validation removes its field from
	 * the record once verified — and whether that runs before or after our hook
	 * depends on registration order.
	 *
	 * @param object $record Elementor Pro form record.
	 * @return array Field type strings.
	 */
	private function field_types( $record ): array {
		$types = array();

		if ( is_object( $record ) && method_exists( $record, 'get_form_settings' ) ) {
			$form_fields = $record->get_form_settings( 'form_fields' );

			if ( is_array( $form_fields ) ) {
				foreach ( $form_fields as $field ) {
					if ( is_array( $field ) && ! empty( $field['field_type'] ) ) {
						$types[] = (string) $field['field_type'];
					}
				}
			}
		}

		if ( is_object( $record ) && method_exists( $record, 'get' ) ) {
			$fields = $record->get( 'fields' );

			if ( is_array( $fields ) ) {
				foreach ( $fields as $field ) {
					if ( is_array( $field ) && ! empty( $field['type'] ) ) {
						$types[] = (string) $field['type'];
					}
				}
			}
		}

		return array_values( array_unique( $types ) );
	}
}
