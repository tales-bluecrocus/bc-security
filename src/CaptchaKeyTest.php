<?php
/**
 * Test CAPTCHA keys with a real token from the administrator's own browser.
 *
 * Google cannot validate a secret without a genuine token: for any made-up token
 * it answers "invalid-input-response" whatever the secret, and a genuine token
 * checked with the wrong secret gets the same answer. So the only honest test is
 * the real flow: a same-origin probe page loads the provider script with the typed
 * site key and produces a token (the administrator ticks the box for v2 and
 * Turnstile), then the server checks that token with the typed secret. A pair is
 * marked verified only when the provider says success.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class CaptchaKeyTest {

	/**
	 * admin-post action serving the probe page.
	 */
	const PROBE_ACTION = 'bc_captcha_probe';

	/**
	 * admin-ajax action checking the token.
	 */
	const TEST_ACTION = 'bc_test_captcha';

	/**
	 * @var CaptchaProvider
	 */
	private $captcha;

	/**
	 * @param CaptchaProvider $captcha CAPTCHA provider.
	 */
	public function __construct( CaptchaProvider $captcha ) {
		$this->captcha = $captcha;
	}

	/**
	 * Register the admin handlers.
	 */
	public function register(): void {
		add_action( 'admin_post_' . self::PROBE_ACTION, array( $this, 'render_probe' ) );
		add_action( 'wp_ajax_' . self::TEST_ACTION, array( $this, 'handle_test' ) );
	}

	/**
	 * Base URL of the probe page, with its nonce.
	 *
	 * @return string
	 */
	public static function probe_url(): string {
		return add_query_arg(
			array(
				'action'   => self::PROBE_ACTION,
				'_wpnonce' => wp_create_nonce( self::PROBE_ACTION ),
			),
			admin_url( 'admin-post.php' )
		);
	}

	/**
	 * Serve the probe page loaded into the Test Keys iframe.
	 */
	public function render_probe(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Verified below.
		$pair     = isset( $_GET['pair'] ) ? sanitize_key( wp_unslash( $_GET['pair'] ) ) : '';
		$provider = isset( $_GET['provider'] ) ? sanitize_key( wp_unslash( $_GET['provider'] ) ) : '';
		$site_key = isset( $_GET['site_key'] ) ? CaptchaSettings::clean_key( wp_unslash( $_GET['site_key'] ) ) : '';
		$probe    = isset( $_GET['probe'] ) ? sanitize_key( wp_unslash( $_GET['probe'] ) ) : '';
		$nonce    = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';
		// phpcs:enable

		$error = '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $nonce, self::PROBE_ACTION ) ) {
			$error = 'expired';
		} elseif ( ! $this->provider_allowed( $pair, $provider ) || ! preg_match( '/^[A-Za-z0-9_-]{20,64}$/', $site_key ) ) {
			$error = 'bad-input';
		}

		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'X-Frame-Options: SAMEORIGIN' );

		$this->print_probe_page( $pair, $provider, $site_key, $probe, $error );
		exit;
	}

	/**
	 * Check a token produced by the probe against the typed secret.
	 *
	 * Tests the values currently in the form rather than the saved ones, so a
	 * pasted key can be checked before committing to it. Saving is separate.
	 */
	public function handle_test(): void {
		check_ajax_referer( self::TEST_ACTION, 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'You do not have permission to test keys.' ), 403 );
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified above.
		$pair     = isset( $_POST['pair'] ) ? sanitize_key( wp_unslash( $_POST['pair'] ) ) : '';
		$provider = isset( $_POST['provider'] ) ? sanitize_key( wp_unslash( $_POST['provider'] ) ) : '';
		$site_key = isset( $_POST['site_key'] ) ? CaptchaSettings::clean_key( wp_unslash( $_POST['site_key'] ) ) : '';
		$secret   = isset( $_POST['secret'] ) ? CaptchaSettings::clean_key( wp_unslash( $_POST['secret'] ) ) : '';
		$token    = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		// phpcs:enable

		if ( ! $this->provider_allowed( $pair, $provider ) ) {
			wp_send_json_error( array( 'message' => 'Choose a CAPTCHA provider first.' ) );
		}

		$result  = $this->captcha->test_pair( $pair, $provider, $site_key, $secret, $token );
		$payload = array(
			'message' => $result['message'],
			'status'  => $this->captcha->pair_status( $pair ),
		);

		if ( ! empty( $result['ok'] ) ) {
			wp_send_json_success( $payload );
		}

		wp_send_json_error( $payload );
	}

	/**
	 * Check that a provider belongs in a pair.
	 *
	 * @param string $pair     'main' or 'v3'.
	 * @param string $provider Provider slug.
	 * @return bool
	 */
	private function provider_allowed( string $pair, string $provider ): bool {
		if ( 'v3' === $pair ) {
			return 'recaptcha_v3' === $provider;
		}

		return 'main' === $pair && in_array( $provider, CaptchaSettings::MAIN_PROVIDERS, true );
	}

	/**
	 * Print the bare probe page.
	 *
	 * @param string $pair     'main' or 'v3'.
	 * @param string $provider Provider slug.
	 * @param string $site_key Typed site key.
	 * @param string $probe    Probe id echoed back to the parent.
	 * @param string $error    Pre-flight error code, or empty.
	 */
	private function print_probe_page( string $pair, string $provider, string $site_key, string $probe, string $error ): void {
		$config = array(
			'provider' => $provider,
			'site'     => $site_key,
			'probe'    => $probe,
			'error'    => $error,
		);

		if ( 'turnstile' === $provider ) {
			$script = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=bcProbeLoad';
		} elseif ( 'recaptcha_v3' === $provider ) {
			$script = 'https://www.google.com/recaptcha/api.js?onload=bcProbeLoad&render=' . rawurlencode( $site_key );
		} else {
			$script = 'https://www.google.com/recaptcha/api.js?onload=bcProbeLoad&render=explicit';
		}
		?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CAPTCHA key test</title>
<style>html,body{margin:0;padding:0;background:transparent;}</style>
</head>
<body>
<div id="bc-probe-widget"></div>
<script>
(function () {
	var P = <?php echo wp_json_encode( $config ); ?>;
	var finished = false;

	function send(message) {
		if (finished) return;
		if (message.type !== 'ready') finished = true;
		message.bcProbe = P.probe;
		try { window.parent.postMessage(message, window.location.origin); } catch (e) {}
	}

	if (P.error) {
		send({type: 'error', code: P.error});
		return;
	}

	// Report the page height so the parent can grow the iframe: a v2 image
	// challenge opens well below the checkbox and would otherwise be cut off.
	var lastHeight = 0;
	setInterval(function () {
		if (finished) return;
		var height = Math.max(document.documentElement.scrollHeight, document.body ? document.body.scrollHeight : 0);
		if (height === lastHeight) return;
		lastHeight = height;
		try { window.parent.postMessage({bcProbe: P.probe, type: 'size', height: height}, window.location.origin); } catch (e) {}
	}, 250);

	var timer = setTimeout(function () {
		send({type: 'timeout'});
	}, P.provider === 'recaptcha_v3' ? 15000 : 180000);

	function done(message) {
		clearTimeout(timer);
		send(message);
	}

	window.bcProbeBlocked = function () {
		done({type: 'script-blocked'});
	};

	window.bcProbeLoad = function () {
		try {
			if (P.provider === 'turnstile') {
				send({type: 'ready'});
				turnstile.render('#bc-probe-widget', {
					sitekey: P.site,
					callback: function (token) { done({type: 'token', token: token}); },
					'error-callback': function () { done({type: 'error', code: 'widget-error'}); }
				});
			} else if (P.provider === 'recaptcha_v2') {
				send({type: 'ready'});
				grecaptcha.render('bc-probe-widget', {
					sitekey: P.site,
					callback: function (token) { done({type: 'token', token: token}); },
					'error-callback': function () { done({type: 'error', code: 'widget-error'}); }
				});
			} else {
				grecaptcha.ready(function () {
					try {
						grecaptcha.execute(P.site, {action: 'bc_key_test'}).then(
							function (token) { done({type: 'token', token: token}); },
							function () { done({type: 'error', code: 'execute-rejected'}); }
						);
					} catch (e) {
						done({type: 'error', code: 'execute-rejected'});
					}
				});
			}
		} catch (e) {
			done({type: 'error', code: 'widget-error'});
		}
	};
})();
</script>
<?php if ( '' === $error ) : ?>
<script src="<?php echo esc_url( $script ); ?>" async defer onerror="bcProbeBlocked()"></script>
<?php endif; ?>
</body>
</html>
		<?php
	}
}
