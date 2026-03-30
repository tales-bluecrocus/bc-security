<?php
/**
 * CAPTCHA provider — reCAPTCHA v3 and Cloudflare Turnstile integration.
 *
 * Abstracts CAPTCHA verification behind a unified interface.
 * When disabled (default), all methods are no-ops and verify() returns success.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class CaptchaProvider {

	/**
	 * Get CAPTCHA settings with defaults.
	 *
	 * @return array Settings array.
	 */
	private function get_settings(): array {
		$defaults = array(
			'captcha_provider'        => 'off',
			'captcha_site_key'        => '',
			'captcha_secret_key'      => '',
			'captcha_score_threshold' => 0.5,
			'captcha_on_login'        => false,
		);

		$settings = get_option( 'bc_security_settings', array() );

		return wp_parse_args( $settings, $defaults );
	}

	/**
	 * Get the active CAPTCHA provider.
	 *
	 * @return string 'recaptcha_v3', 'turnstile', or 'off'.
	 */
	public function get_provider(): string {
		$settings = $this->get_settings();
		return $settings['captcha_provider'];
	}

	/**
	 * Check if CAPTCHA is enabled.
	 *
	 * @return bool
	 */
	public function is_enabled(): bool {
		return $this->get_provider() !== 'off';
	}

	/**
	 * Check if CAPTCHA is enabled for the login page.
	 *
	 * @return bool
	 */
	public function is_login_enabled(): bool {
		$settings = $this->get_settings();
		return $this->is_enabled() && ! empty( $settings['captcha_on_login'] );
	}

	/**
	 * Register WordPress hooks for CAPTCHA script loading.
	 */
	public function register(): void {
		if ( ! $this->is_enabled() ) {
			return;
		}

		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		add_action( 'wp_footer', array( $this, 'render_token_js' ) );

		if ( $this->is_login_enabled() ) {
			add_action( 'login_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
			add_action( 'login_footer', array( $this, 'render_token_js' ) );
		}
	}

	/**
	 * Enqueue the CAPTCHA provider's JavaScript.
	 */
	public function enqueue_scripts(): void {
		$settings = $this->get_settings();
		$provider = $settings['captcha_provider'];
		$site_key = $settings['captcha_site_key'];

		if ( empty( $site_key ) ) {
			return;
		}

		if ( $provider === 'recaptcha_v3' ) {
			wp_enqueue_script(
				'bc-recaptcha',
				'https://www.google.com/recaptcha/api.js?render=' . urlencode( $site_key ),
				array(),
				null,
				true
			);
		} elseif ( $provider === 'turnstile' ) {
			wp_enqueue_script(
				'bc-turnstile',
				'https://challenges.cloudflare.com/turnstile/v0/api.js',
				array(),
				null,
				true
			);
		}
	}

	/**
	 * Render the inline JavaScript for token injection.
	 */
	public function render_token_js(): void {
		$settings = $this->get_settings();
		$provider = $settings['captcha_provider'];
		$site_key = $settings['captcha_site_key'];

		if ( empty( $site_key ) ) {
			return;
		}

		if ( $provider === 'recaptcha_v3' ) {
			$this->render_recaptcha_js( $site_key );
		} elseif ( $provider === 'turnstile' ) {
			$this->render_turnstile_js( $site_key );
		}
	}

	/**
	 * Render reCAPTCHA v3 token injection script.
	 *
	 * @param string $site_key reCAPTCHA site key.
	 */
	private function render_recaptcha_js( string $site_key ): void {
		?>
		<script>
		(function() {
			function bcAddRecaptchaToken(form) {
				if (form.querySelector('input[name="bc_captcha_token"]')) return;
				form.addEventListener('submit', function(e) {
					var existing = form.querySelector('input[name="bc_captcha_token"]');
					if (existing && existing.value) return;
					e.preventDefault();
					grecaptcha.ready(function() {
						grecaptcha.execute(<?php echo wp_json_encode( $site_key ); ?>, {action: 'submit'}).then(function(token) {
							var input = form.querySelector('input[name="bc_captcha_token"]');
							if (!input) {
								input = document.createElement('input');
								input.type = 'hidden';
								input.name = 'bc_captcha_token';
								form.appendChild(input);
							}
							input.value = token;
							var btn = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
							if (btn) {
								btn.click();
							} else if (form.requestSubmit) {
								form.requestSubmit();
							} else {
								form.submit();
							}
						});
					});
				});
			}
			document.addEventListener('DOMContentLoaded', function() {
				var forms = document.querySelectorAll('form');
				for (var i = 0; i < forms.length; i++) {
					bcAddRecaptchaToken(forms[i]);
				}
			});
		})();
		</script>
		<?php
	}

	/**
	 * Render Cloudflare Turnstile token injection script.
	 *
	 * @param string $site_key Turnstile site key.
	 */
	private function render_turnstile_js( string $site_key ): void {
		?>
		<script>
		(function() {
			document.addEventListener('DOMContentLoaded', function() {
				if (typeof turnstile === 'undefined') return;
				var forms = document.querySelectorAll('form');
				for (var i = 0; i < forms.length; i++) {
					var container = document.createElement('div');
					container.className = 'cf-turnstile';
					container.setAttribute('data-sitekey', <?php echo wp_json_encode( $site_key ); ?>);
					container.setAttribute('data-size', 'invisible');
					forms[i].appendChild(container);
					turnstile.render(container);
				}
			});
		})();
		</script>
		<?php
	}

	/**
	 * Verify the CAPTCHA token from the current request.
	 *
	 * @return array Verification result with 'success' (bool), 'score' (float), and optionally 'reason' (string).
	 */
	public function verify(): array {
		$pass = array( 'success' => true, 'score' => 1.0 );

		if ( ! $this->is_enabled() ) {
			return $pass;
		}

		$settings = $this->get_settings();

		if ( empty( $settings['captcha_secret_key'] ) ) {
			return $pass;
		}

		$token = $this->get_token();
		if ( empty( $token ) ) {
			return array( 'success' => false, 'score' => 0.0, 'reason' => 'captcha_missing' );
		}

		$provider = $settings['captcha_provider'];

		if ( $provider === 'recaptcha_v3' ) {
			return $this->verify_recaptcha( $token, $settings );
		} elseif ( $provider === 'turnstile' ) {
			return $this->verify_turnstile( $token, $settings );
		}

		return $pass;
	}

	/**
	 * Read the CAPTCHA token from POST data.
	 *
	 * @return string Token value or empty string.
	 */
	private function get_token(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified by the form plugin.
		if ( ! empty( $_POST['bc_captcha_token'] ) ) {
			return sanitize_text_field( wp_unslash( $_POST['bc_captcha_token'] ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified by the form plugin.
		if ( ! empty( $_POST['cf-turnstile-response'] ) ) {
			return sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) );
		}

		return '';
	}

	/**
	 * Verify a token against the Google reCAPTCHA v3 API.
	 *
	 * @param string $token   CAPTCHA token from client.
	 * @param array  $settings Plugin settings.
	 * @return array Verification result.
	 */
	private function verify_recaptcha( string $token, array $settings ): array {
		$response = wp_remote_post( 'https://www.google.com/recaptcha/api/siteverify', array(
			'body' => array(
				'secret'   => $settings['captcha_secret_key'],
				'response' => $token,
				'remoteip' => isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '',
			),
			'timeout' => 5,
		) );

		// Fail-open on API error.
		if ( is_wp_error( $response ) ) {
			return array( 'success' => true, 'score' => 1.0 );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body ) || empty( $body['success'] ) ) {
			return array( 'success' => false, 'score' => 0.0, 'reason' => 'captcha_failed' );
		}

		$score     = isset( $body['score'] ) ? (float) $body['score'] : 0.0;
		$threshold = (float) $settings['captcha_score_threshold'];

		if ( $score < $threshold ) {
			return array( 'success' => false, 'score' => $score, 'reason' => 'captcha_score:' . $score );
		}

		return array( 'success' => true, 'score' => $score );
	}

	/**
	 * Verify a token against the Cloudflare Turnstile API.
	 *
	 * @param string $token   CAPTCHA token from client.
	 * @param array  $settings Plugin settings.
	 * @return array Verification result.
	 */
	private function verify_turnstile( string $token, array $settings ): array {
		$response = wp_remote_post( 'https://challenges.cloudflare.com/turnstile/v0/siteverify', array(
			'body' => array(
				'secret'   => $settings['captcha_secret_key'],
				'response' => $token,
				'remoteip' => isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '',
			),
			'timeout' => 5,
		) );

		// Fail-open on API error.
		if ( is_wp_error( $response ) ) {
			return array( 'success' => true, 'score' => 1.0 );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body ) || empty( $body['success'] ) ) {
			return array( 'success' => false, 'score' => 0.0, 'reason' => 'captcha_failed' );
		}

		return array( 'success' => true, 'score' => 1.0 );
	}
}
