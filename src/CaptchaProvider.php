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
	 * Interception is conditional: the form is only held back when the library is
	 * actually usable, and any timeout or rejection releases it. A form that cannot
	 * obtain a token submits without one and is rejected server-side as
	 * captcha_missing, which is visible in the logs and recoverable by retrying.
	 * A form frozen by an unresolved promise is neither.
	 *
	 * The token is single-use: it is cleared after the replay dispatch so that a
	 * second submission of an AJAX form obtains a fresh one instead of replaying
	 * the old token and being rejected as timeout-or-duplicate.
	 *
	 * @param string $site_key reCAPTCHA site key.
	 */
	private function render_recaptcha_js( string $site_key ): void {
		?>
		<script>
		(function() {
			var siteKey   = <?php echo wp_json_encode( $site_key ); ?>;
			var timeoutMs = 10000;
			var fieldName = 'bc_captcha_token';
			var givenUp   = false;

			function bcReady() {
				return typeof grecaptcha !== 'undefined' &&
					typeof grecaptcha.ready === 'function' &&
					typeof grecaptcha.execute === 'function';
			}

			function bcWarn(message) {
				if (window.console && console.warn) {
					console.warn('bc-security: ' + message);
				}
			}

			function bcSetToken(form, token) {
				var input = form.querySelector('input[name="' + fieldName + '"]');
				if (!input) {
					input = document.createElement('input');
					input.type = 'hidden';
					input.name = fieldName;
					form.appendChild(input);
				}
				input.value = token;
			}

			function bcResubmit(form) {
				var btn = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
				if (btn) {
					btn.click();
				} else if (form.requestSubmit) {
					form.requestSubmit();
				} else {
					form.submit();
				}
			}

			function bcBind(form) {
				if (form.getAttribute('data-bc-captcha') === '1') return;
				form.setAttribute('data-bc-captcha', '1');

				form.addEventListener('submit', function(e) {
					// Replay pass: the token is attached, let every other handler run.
					if (form.bcCaptchaReplay) {
						form.bcCaptchaReplay = false;
						// Clear after the current dispatch so a second submission of an
						// AJAX form gets a fresh token rather than a duplicate.
						setTimeout(function() {
							var input = form.querySelector('input[name="' + fieldName + '"]');
							if (input) input.value = '';
						}, 0);
						return;
					}

					// A request is already in flight; drop the duplicate click.
					if (form.bcCaptchaPending) {
						e.preventDefault();
						return;
					}

					// Never hold a form hostage to a library that is not there.
					if (givenUp || !bcReady()) return;

					e.preventDefault();
					form.bcCaptchaPending = true;

					var done = false;

					function finish(token) {
						if (done) return;
						done = true;
						clearTimeout(timer);
						form.bcCaptchaPending = false;
						form.bcCaptchaReplay  = true;
						bcSetToken(form, token || '');
						bcResubmit(form);
					}

					var timer = setTimeout(function() {
						givenUp = true;
						bcWarn('reCAPTCHA timed out after ' + timeoutMs + 'ms; submitting without a token.');
						finish('');
					}, timeoutMs);

					try {
						grecaptcha.ready(function() {
							try {
								grecaptcha.execute(siteKey, {action: 'submit'}).then(
									function(token) {
										finish(token);
									},
									function() {
										givenUp = true;
										bcWarn('reCAPTCHA execute() was rejected; submitting without a token.');
										finish('');
									}
								);
							} catch (err) {
								givenUp = true;
								bcWarn('reCAPTCHA execute() threw; submitting without a token.');
								finish('');
							}
						});
					} catch (err) {
						givenUp = true;
						bcWarn('grecaptcha.ready() threw; submitting without a token.');
						finish('');
					}
				});
			}

			document.addEventListener('DOMContentLoaded', function() {
				var forms = document.querySelectorAll('form');
				for (var i = 0; i < forms.length; i++) {
					bcBind(forms[i]);
				}
			});
		})();
		</script>
		<?php
	}

	/**
	 * Render Cloudflare Turnstile token injection script.
	 *
	 * Unlike the reCAPTCHA path this never intercepts submission — the widget
	 * populates cf-turnstile-response on its own — so there is no way to deadlock
	 * a form here. What it does need is a reset after each submission: Turnstile
	 * tokens are single-use, so an AJAX form that stays on the page would
	 * otherwise replay a spent token and be rejected as timeout-or-duplicate.
	 *
	 * @param string $site_key Turnstile site key.
	 */
	private function render_turnstile_js( string $site_key ): void {
		?>
		<script>
		(function() {
			var siteKey = <?php echo wp_json_encode( $site_key ); ?>;

			function bcWarn(message) {
				if (window.console && console.warn) {
					console.warn('bc-security: ' + message);
				}
			}

			document.addEventListener('DOMContentLoaded', function() {
				if (typeof turnstile === 'undefined' || typeof turnstile.render !== 'function') {
					bcWarn('Turnstile library unavailable; forms submit without a token.');
					return;
				}

				var forms = document.querySelectorAll('form');

				for (var i = 0; i < forms.length; i++) {
					(function(form) {
						if (form.getAttribute('data-bc-captcha') === '1') return;
						form.setAttribute('data-bc-captcha', '1');

						var container = document.createElement('div');
						container.className = 'cf-turnstile';
						container.setAttribute('data-sitekey', siteKey);
						container.setAttribute('data-size', 'invisible');
						form.appendChild(container);

						var widgetId;

						try {
							widgetId = turnstile.render(container);
						} catch (err) {
							bcWarn('Turnstile render() failed; this form submits without a token.');
							return;
						}

						form.addEventListener('submit', function() {
							// Reset after the current dispatch so the widget issues a
							// fresh token for any subsequent submission of this form.
							setTimeout(function() {
								try {
									if (typeof turnstile.reset === 'function') {
										turnstile.reset(widgetId);
									}
								} catch (err) {
									bcWarn('Turnstile reset() failed; the next submission may be rejected as a duplicate.');
								}
							}, 0);
						});
					})(forms[i]);
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
