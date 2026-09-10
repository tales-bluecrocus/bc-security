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
	 * Transient holding the most recent CAPTCHA configuration fault.
	 */
	const ERROR_TRANSIENT = 'bc_captcha_last_error';

	/**
	 * Provider error codes that indicate a configuration or infrastructure fault
	 * on our side rather than a verdict about the visitor.
	 *
	 * A visitor cannot provoke any of these once is_plausible_token() has run:
	 * the secret key and the request shape are entirely under the site's control.
	 *
	 * @var array
	 */
	private static $config_error_codes = array(
		'missing-input-secret',
		'invalid-input-secret',
		'invalid-parsed-secret',
		'invalid-keys',
		'invalid-widget-id',
		'bad-request',
		'internal-error',
	);

	/**
	 * @var IpResolver|null
	 */
	private $ip_resolver;

	/**
	 * @param IpResolver|null $ip_resolver Optional IP detection dependency.
	 */
	public function __construct( ?IpResolver $ip_resolver = null ) {
		$this->ip_resolver = $ip_resolver;
	}

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
			'captcha_on_lostpassword' => false,
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
	 * Check if CAPTCHA is enabled for the lost-password form.
	 *
	 * @return bool
	 */
	public function is_lostpassword_enabled(): bool {
		$settings = $this->get_settings();
		return $this->is_enabled() && ! empty( $settings['captcha_on_lostpassword'] );
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

		// Both toggles live on wp-login.php, so either one requires the scripts.
		// Without this, enabling only the lost-password toggle would print no
		// script, send no token, and block every password reset on the site.
		if ( $this->is_login_enabled() || $this->is_lostpassword_enabled() ) {
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
	 * Fails open — with reason 'captcha_unavailable' — when the provider or our own
	 * keys are at fault, and records the cause for the admin notice. Fails closed on
	 * a genuine bot verdict: a missing token, an implausible one, or a rejection the
	 * provider attributes to the submitted response.
	 *
	 * @return array Verification result with 'success' (bool), 'score' (float), and optionally 'reason' (string).
	 */
	public function verify(): array {
		$pass = array( 'success' => true, 'score' => 1.0 );

		if ( ! $this->is_enabled() ) {
			return $pass;
		}

		$settings = $this->get_settings();

		// A missing site key means enqueue_scripts() and render_token_js() both
		// bailed, so no script was printed and no token can possibly exist —
		// failing closed here would block every submission on the site. A missing
		// secret key means there is nothing to verify against.
		if ( empty( $settings['captcha_site_key'] ) || empty( $settings['captcha_secret_key'] ) ) {
			return $pass;
		}

		$token = $this->get_token();
		if ( empty( $token ) ) {
			return array( 'success' => false, 'score' => 0.0, 'reason' => 'captcha_missing' );
		}

		// Reject implausible tokens locally so a bot cannot provoke a bad-request
		// response, which is classified below as a configuration fault and fails
		// open. If this check is ever loosened, bad-request must move to the
		// fail-closed list.
		if ( ! $this->is_plausible_token( $token ) ) {
			return array( 'success' => false, 'score' => 0.0, 'reason' => 'captcha_failed' );
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
	 * Check whether a secret key is accepted by its provider.
	 *
	 * Deliberately sends an invalid token. If the provider rejects the *token*, the
	 * secret was accepted and the key is good; if it rejects the *secret*, the key
	 * is broken. Takes the values as arguments rather than reading settings, so an
	 * admin can test a pasted key before saving it.
	 *
	 * @param string $provider   Provider slug.
	 * @param string $secret_key Secret key to test.
	 * @return array Array with 'ok' (bool) and 'message' (string).
	 */
	public function test_keys( string $provider, string $secret_key ): array {
		$endpoints = array(
			'recaptcha_v3' => 'https://www.google.com/recaptcha/api/siteverify',
			'turnstile'    => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
		);

		if ( ! isset( $endpoints[ $provider ] ) ) {
			return array( 'ok' => false, 'message' => 'Select a CAPTCHA provider first.' );
		}

		if ( empty( $secret_key ) ) {
			return array( 'ok' => false, 'message' => 'Enter a secret key first.' );
		}

		$response = wp_remote_post( $endpoints[ $provider ], array(
			'body' => array(
				'secret'   => $secret_key,
				'response' => 'bc-security-key-test',
			),
			'timeout' => 10,
		) );

		if ( is_wp_error( $response ) ) {
			return array(
				'ok'      => false,
				'message' => 'Could not reach the provider: ' . $response->get_error_message(),
			);
		}

		$status = (int) wp_remote_retrieve_response_code( $response );

		if ( $status < 200 || $status > 299 ) {
			return array( 'ok' => false, 'message' => "Provider returned HTTP {$status}." );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) ) {
			return array( 'ok' => false, 'message' => 'Provider returned a response we could not read.' );
		}

		$codes = isset( $body['error-codes'] ) && is_array( $body['error-codes'] )
			? array_map( 'strval', $body['error-codes'] )
			: array();

		$secret_codes = array( 'invalid-input-secret', 'missing-input-secret', 'invalid-parsed-secret', 'invalid-keys' );

		if ( array_intersect( $codes, $secret_codes ) ) {
			return array(
				'ok'      => false,
				'message' => 'Secret key rejected (' . implode( ', ', $codes ) . '). Forms will fail open until this is fixed.',
			);
		}

		// The secret was accepted — the only complaint is our deliberately bad token.
		$token_codes = array( 'invalid-input-response', 'missing-input-response', 'timeout-or-duplicate', 'bad-request' );

		if ( array_intersect( $codes, $token_codes ) ) {
			return array( 'ok' => true, 'message' => 'Secret key accepted. CAPTCHA verification is working.' );
		}

		if ( empty( $codes ) ) {
			return array( 'ok' => false, 'message' => 'Provider gave no verdict. Try again shortly.' );
		}

		return array( 'ok' => false, 'message' => 'Unexpected response: ' . implode( ', ', $codes ) );
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
	 * Check that a token looks like something a CAPTCHA provider could have issued.
	 *
	 * @param string $token Submitted token.
	 * @return bool
	 */
	private function is_plausible_token( string $token ): bool {
		if ( strlen( $token ) > 4096 ) {
			return false;
		}

		return (bool) preg_match( '/^[A-Za-z0-9_\-\.=~]+$/', $token );
	}

	/**
	 * Get the client IP for the provider's optional remoteip parameter.
	 *
	 * Uses IpResolver so the value matches what the rest of the plugin logs —
	 * REMOTE_ADDR is the CDN edge on every Cloudflare-fronted site. The parameter
	 * is advisory: IpResolver trusts X-Forwarded-For, so a spoofed header only
	 * degrades the provider's own risk signal and cannot bypass verification.
	 *
	 * @return string Client IP, or an empty string when unresolved.
	 */
	private function get_remote_ip(): string {
		$resolver = $this->ip_resolver ? $this->ip_resolver : new IpResolver();
		$ip       = $resolver->get_client_ip();

		return $ip === '0.0.0.0' ? '' : $ip;
	}

	/**
	 * Decode and classify a siteverify response.
	 *
	 * Configuration and infrastructure faults fail OPEN and are recorded for the
	 * admin notice — they are our problem, not the visitor's, and blocking real
	 * people because a key expired is worse than briefly losing the check.
	 * Genuine bot verdicts fail CLOSED.
	 *
	 * @param array|\WP_Error $response Raw wp_remote_post() result.
	 * @param string          $provider Provider slug, for the error record.
	 * @return array Array with 'body' (decoded body, or null) and 'result'
	 *               (a verify() result to return as-is, or null to continue).
	 */
	private function parse_siteverify( $response, string $provider ): array {
		$open = array(
			'body'   => null,
			'result' => array( 'success' => true, 'score' => 1.0, 'reason' => 'captcha_unavailable' ),
		);

		if ( is_wp_error( $response ) ) {
			$this->record_error( $provider, array( 'request-failed' ), $response->get_error_message() );
			return $open;
		}

		$status = (int) wp_remote_retrieve_response_code( $response );

		if ( $status < 200 || $status > 299 ) {
			$this->record_error( $provider, array( 'http-' . $status ), '' );
			return $open;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) ) {
			$this->record_error( $provider, array( 'unparseable-response' ), '' );
			return $open;
		}

		if ( ! empty( $body['success'] ) ) {
			return array( 'body' => $body, 'result' => null );
		}

		$codes = isset( $body['error-codes'] ) && is_array( $body['error-codes'] )
			? array_map( 'strval', $body['error-codes'] )
			: array();

		// An empty error-codes array is undocumented for both providers, so treat
		// it as a fault rather than silently blocking real visitors.
		if ( empty( $codes ) || array_intersect( $codes, self::$config_error_codes ) ) {
			$this->record_error( $provider, empty( $codes ) ? array( 'no-error-code' ) : $codes, '' );
			return $open;
		}

		// invalid-input-response, missing-input-response, timeout-or-duplicate.
		return array(
			'body'   => null,
			'result' => array( 'success' => false, 'score' => 0.0, 'reason' => 'captcha_failed' ),
		);
	}

	/**
	 * Record the most recent CAPTCHA configuration fault for the admin notice.
	 *
	 * A transient rather than a log row: this is a site-configuration problem, not
	 * a submission, and LogsTable renders any non-blocked status as a green "Sent"
	 * badge, so a fault would display as a successful send. Rewritten only when the
	 * payload changes, so a spam flood against a broken key cannot turn into one
	 * database write per request.
	 *
	 * @param string $provider Provider slug.
	 * @param array  $codes    Provider error codes, or a synthetic code.
	 * @param string $detail   Optional extra detail (WP_Error message).
	 */
	private function record_error( string $provider, array $codes, string $detail ): void {
		$record = array(
			'provider' => $provider,
			'codes'    => array_values( $codes ),
			'detail'   => $detail,
			'time'     => time(),
		);

		$existing = get_transient( self::ERROR_TRANSIENT );

		if ( is_array( $existing )
			&& isset( $existing['provider'], $existing['codes'] )
			&& $existing['provider'] === $record['provider']
			&& $existing['codes'] === $record['codes'] ) {
			return;
		}

		set_transient( self::ERROR_TRANSIENT, $record, 6 * HOUR_IN_SECONDS );
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
				'remoteip' => $this->get_remote_ip(),
			),
			'timeout' => 5,
		) );

		$parsed = $this->parse_siteverify( $response, 'recaptcha_v3' );

		if ( $parsed['result'] !== null ) {
			return $parsed['result'];
		}

		$score     = isset( $parsed['body']['score'] ) ? (float) $parsed['body']['score'] : 0.0;
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
				'remoteip' => $this->get_remote_ip(),
			),
			'timeout' => 5,
		) );

		$parsed = $this->parse_siteverify( $response, 'turnstile' );

		if ( $parsed['result'] !== null ) {
			return $parsed['result'];
		}

		return array( 'success' => true, 'score' => 1.0 );
	}
}
