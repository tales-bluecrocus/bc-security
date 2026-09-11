<?php
/**
 * CAPTCHA provider — Google reCAPTCHA (v2 checkbox, v3) and Cloudflare Turnstile.
 *
 * Nothing here is enforced unless the key pair involved has passed Test Keys on
 * this site. Until then a surface is inactive and the plugin's other layers keep
 * working: rate limits for login and password reset, the honeypot and keyword
 * filter for contact forms.
 *
 * Why the gate exists: Google answers "invalid-input-response" for a forged token
 * and for a genuine token checked against the wrong secret alike, and a wrong site
 * key simply produces no token. A bad or retired reCAPTCHA key is therefore
 * indistinguishable from a bot on any single request. The one reliable moment to
 * catch it is before it is switched on, with a real token from a real browser.
 *
 * Surfaces:
 *   - Login: the main checkbox, only for IPs over the brute-force limit (BruteForce).
 *   - Lost password: the main checkbox on wp-login.php (PasswordReset).
 *   - Contact forms: off, the main checkbox, or invisible reCAPTCHA v3 (here).
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
	 * Field our scripts copy the provider token into. The server reads only this,
	 * so other plugins' g-recaptcha-response or cf-turnstile-response fields can
	 * never be mistaken for ours.
	 */
	const TOKEN_FIELD = 'bc_captcha_token';

	/**
	 * Field our scripts use to report why no token could be obtained.
	 */
	const ERROR_FIELD = 'bc_captcha_error';

	/**
	 * Codes a visitor's browser may report when the provider library loaded but no
	 * token could be obtained. A library that never loaded at all (ad blocker,
	 * network) reports nothing: that says nothing about our keys.
	 */
	const CLIENT_ERROR_CODES = array( 'v3-timeout', 'v3-rejected', 'v3-no-execute', 'widget-error', 'widget-render-failed' );

	/**
	 * Provider error codes that indicate a configuration or infrastructure fault
	 * on our side rather than a verdict about the visitor.
	 *
	 * Only Cloudflare actually reports a bad secret; Google never does (see the
	 * class docblock). A visitor cannot provoke any of these once
	 * is_plausible_token() has run.
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
	 * siteverify endpoints.
	 *
	 * @var array
	 */
	private static $endpoints = array(
		'recaptcha_v2' => 'https://www.google.com/recaptcha/api/siteverify',
		'recaptcha_v3' => 'https://www.google.com/recaptcha/api/siteverify',
		'turnstile'    => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
	);

	/**
	 * @var IpResolver
	 */
	private $ip_resolver;

	/**
	 * @var CaptchaVerifiedKeys
	 */
	private $verified;

	/**
	 * @var CaptchaHealth
	 */
	private $health;

	/**
	 * @var ElementorCaptcha
	 */
	private $elementor;

	/**
	 * Whether the widget script has been printed on this page.
	 *
	 * @var bool
	 */
	private $widget_js_printed = false;

	/**
	 * @param IpResolver|null          $ip_resolver IP detection.
	 * @param CaptchaVerifiedKeys|null $verified    Verified key pairs.
	 * @param CaptchaHealth|null       $health      Verification health tracking.
	 * @param ElementorCaptcha|null    $elementor   Elementor reCAPTCHA detection.
	 */
	public function __construct( ?IpResolver $ip_resolver = null, ?CaptchaVerifiedKeys $verified = null, ?CaptchaHealth $health = null, ?ElementorCaptcha $elementor = null ) {
		$this->ip_resolver = $ip_resolver ? $ip_resolver : new IpResolver();
		$this->verified    = $verified ? $verified : new CaptchaVerifiedKeys();
		$this->health      = $health ? $health : new CaptchaHealth();
		$this->elementor   = $elementor ? $elementor : new ElementorCaptcha();
	}

	/* =====================================================================
	 * State
	 * ===================================================================== */

	/**
	 * Fingerprint of the saved keys for a pair.
	 *
	 * @param string $pair 'main' or 'v3'.
	 * @return string
	 */
	public function pair_fingerprint( string $pair ): string {
		$keys = CaptchaSettings::pair( $pair );

		return CaptchaSettings::fingerprint( $pair, $keys['provider'], $keys['site'], $keys['secret'] );
	}

	/**
	 * Status of the saved keys for a pair.
	 *
	 * @param string $pair 'main' or 'v3'.
	 * @return string 'no-keys', 'untested' or 'active'.
	 */
	public function pair_status( string $pair ): string {
		$keys = CaptchaSettings::pair( $pair );

		if ( '' === $keys['site'] || '' === $keys['secret'] ) {
			return 'no-keys';
		}

		return $this->verified->is_verified( $this->pair_fingerprint( $pair ) ) ? 'active' : 'untested';
	}

	/**
	 * Check whether a pair's saved keys have passed Test Keys on this host.
	 *
	 * @param string $pair 'main' or 'v3'.
	 * @return bool
	 */
	public function is_pair_active( string $pair ): bool {
		return 'active' === $this->pair_status( $pair );
	}

	/**
	 * When the saved keys for a pair passed Test Keys.
	 *
	 * @param string $pair 'main' or 'v3'.
	 * @return int Unix time, or 0.
	 */
	public function verified_time( string $pair ): int {
		return $this->verified->time_for( $this->pair_fingerprint( $pair ) );
	}

	/**
	 * The main pair's provider.
	 *
	 * @return string 'recaptcha_v2' or 'turnstile'.
	 */
	public function main_provider(): string {
		$keys = CaptchaSettings::pair( 'main' );

		return $keys['provider'];
	}

	/**
	 * Check whether flagged IPs get a checkbox instead of a lockout on wp-login.php.
	 *
	 * @return bool
	 */
	public function is_login_challenge_active(): bool {
		$settings = CaptchaSettings::get();

		return ! empty( $settings['captcha_login_challenge'] ) && $this->is_pair_active( 'main' );
	}

	/**
	 * Check whether the lost-password form requires the checkbox.
	 *
	 * @return bool
	 */
	public function is_reset_active(): bool {
		$settings = CaptchaSettings::get();

		return ! empty( $settings['captcha_on_lostpassword'] ) && $this->is_pair_active( 'main' );
	}

	/**
	 * The contact-form mode actually in force.
	 *
	 * @return string 'off', 'checkbox' or 'v3' — 'off' unless the pair it needs is active.
	 */
	public function forms_mode(): string {
		$settings = CaptchaSettings::get();
		$mode     = (string) $settings['captcha_forms_mode'];

		if ( 'checkbox' === $mode ) {
			return $this->is_pair_active( 'main' ) ? 'checkbox' : 'off';
		}

		if ( 'v3' === $mode ) {
			return $this->is_pair_active( 'v3' ) ? 'v3' : 'off';
		}

		return 'off';
	}

	/**
	 * The failure streak to warn about, if a pair's keys look broken.
	 *
	 * @param string $pair 'main' or 'v3'.
	 * @return array|null
	 */
	public function health_warning( string $pair ): ?array {
		if ( ! $this->is_pair_active( $pair ) ) {
			return null;
		}

		return $this->health->warning( $pair, $this->pair_fingerprint( $pair ) );
	}

	/* =====================================================================
	 * Contact forms
	 * ===================================================================== */

	/**
	 * Register front-end hooks. Only when a contact-form mode is actually in force:
	 * a site with CAPTCHA off loads no provider script at all.
	 */
	public function register(): void {
		if ( 'off' === $this->forms_mode() ) {
			return;
		}

		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_forms_scripts' ) );
		add_action( 'wp_footer', array( $this, 'render_forms_js' ) );
	}

	/**
	 * Enqueue the provider script for contact forms.
	 */
	public function enqueue_forms_scripts(): void {
		$mode = $this->forms_mode();

		if ( 'checkbox' === $mode ) {
			wp_enqueue_script( 'bc-captcha-widget', $this->widget_script_url( $this->main_provider() ), array(), null, true );
		} elseif ( 'v3' === $mode ) {
			$keys = CaptchaSettings::pair( 'v3' );
			wp_enqueue_script(
				'bc-recaptcha-v3',
				'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $keys['site'] ),
				array(),
				null,
				true
			);
		}
	}

	/**
	 * Print the contact-form script. Runs at wp_footer priority 10, before footer
	 * scripts print at 20, so the provider's onload callback already exists.
	 */
	public function render_forms_js(): void {
		$mode = $this->forms_mode();

		if ( 'checkbox' === $mode ) {
			$this->print_widget_js( 'forms' );
		} elseif ( 'v3' === $mode ) {
			$keys = CaptchaSettings::pair( 'v3' );
			$this->render_v3_js( $keys['site'] );
		}
	}

	/* =====================================================================
	 * The visible checkbox (login escape hatch, lost-password form, forms)
	 * ===================================================================== */

	/**
	 * Enqueue the main provider's script on wp-login.php.
	 */
	public function enqueue_widget_login(): void {
		wp_enqueue_script( 'bc-captcha-widget', $this->widget_script_url( $this->main_provider() ), array(), null, true );

		// The login form is 272px wide inside; both widgets are about 300px.
		wp_add_inline_style( 'login', '#login{width:352px;}' );
	}

	/**
	 * Print the widget container inside a wp-login.php form.
	 */
	public function print_widget_container(): void {
		echo '<div class="bc-captcha-wrap" style="margin:0 0 16px;">'
			. '<div class="bc-captcha-widget"></div>'
			. '<input type="hidden" name="' . esc_attr( self::TOKEN_FIELD ) . '" value="" />'
			. '<input type="hidden" name="' . esc_attr( self::ERROR_FIELD ) . '" value="" />'
			. '</div>';
	}

	/**
	 * Print the shared checkbox script once per page.
	 *
	 * @param string $context 'login', 'reset' or 'forms'.
	 */
	public function print_widget_js( string $context ): void {
		if ( $this->widget_js_printed ) {
			return;
		}

		$keys = CaptchaSettings::pair( 'main' );

		if ( '' === $keys['site'] ) {
			return;
		}

		$this->widget_js_printed = true;

		$config = array(
			'provider' => $keys['provider'],
			'siteKey'  => $keys['site'],
			'context'  => $context,
			'token'    => self::TOKEN_FIELD,
			'error'    => self::ERROR_FIELD,
			'skip'     => $this->elementor->client_skip_config(),
			'msg'      => array(
				'required' => 'Please complete the security check first.',
			),
		);
		?>
		<script>
		(function () {
			var cfg = <?php echo wp_json_encode( $config ); ?>;
			var ready = false;
			var scheduled = false;

			function lib() {
				if (cfg.provider === 'turnstile') {
					return (typeof turnstile !== 'undefined' && turnstile && typeof turnstile.render === 'function') ? turnstile : null;
				}
				return (typeof grecaptcha !== 'undefined' && grecaptcha && typeof grecaptcha.render === 'function') ? grecaptcha : null;
			}

			function field(form, name) {
				var input = form.querySelector('input[name="' + name + '"]');
				if (!input) {
					input = document.createElement('input');
					input.type = 'hidden';
					input.name = name;
					form.appendChild(input);
				}
				return input;
			}

			function note(form, text) {
				var wrap = form.bcWidgetHost ? form.bcWidgetHost.parentNode : null;
				if (!wrap) return;
				var p = wrap.querySelector('.bc-captcha-note');
				if (!text) {
					if (p) p.parentNode.removeChild(p);
					return;
				}
				if (!p) {
					p = document.createElement('p');
					p.className = 'bc-captcha-note';
					p.setAttribute('role', 'alert');
					p.style.cssText = 'margin:6px 0 0;color:#d63638;font-size:13px;';
					wrap.appendChild(p);
				}
				p.textContent = text;
			}

			// Elementor forms carrying their own configured reCAPTCHA are left to
			// Elementor. Mirrors the server-side step-back exactly.
			function hasOwnCaptcha(form) {
				var own = form.querySelector('.elementor-g-recaptcha');
				if (!own) return false;
				return own.getAttribute('data-type') === 'v3' ? !!cfg.skip.v3 : !!cfg.skip.v2;
			}

			function last(form, selector) {
				var found = form.querySelectorAll(selector);
				return found.length ? found[found.length - 1] : null;
			}

			// Where the widget goes. wp-login.php forms carry a server-printed
			// container; contact forms get one just before the submit row.
			function host(form) {
				var existing = form.querySelector('.bc-captcha-widget');
				if (existing) return existing;
				if (cfg.context !== 'forms') return null;

				var anchor = null;
				if (form.classList.contains('elementor-form')) {
					anchor = last(form, '.elementor-field-type-submit');
				} else if (form.classList.contains('wpcf7-form')) {
					var button = last(form, '.wpcf7-submit');
					if (button) {
						var row = button.closest('p');
						anchor = (row && form.contains(row)) ? row : button;
					}
				} else if (form.closest('.gform_wrapper')) {
					anchor = last(form, '.gform_page_footer') || last(form, '.gform_footer');
				} else if (form.classList.contains('frm-show-form')) {
					anchor = last(form, '.frm_submit');
				}
				if (!anchor || !anchor.parentNode) return null;

				var wrap = document.createElement('div');
				wrap.className = 'bc-captcha-wrap';
				wrap.style.cssText = 'margin:0 0 12px;flex:0 0 100%;width:100%;max-width:100%;';
				var widget = document.createElement('div');
				widget.className = 'bc-captcha-widget';
				wrap.appendChild(widget);
				anchor.parentNode.insertBefore(wrap, anchor);
				return widget;
			}

			function render(form) {
				if (form.bcWidget !== undefined) return;
				var api = lib();
				if (!api) return;
				var target = host(form);
				if (!target) return;

				var token = field(form, cfg.token);
				var error = field(form, cfg.error);
				form.bcWidgetHost = target;

				try {
					form.bcWidget = api.render(target, {
						sitekey: cfg.siteKey,
						callback: function (value) {
							token.value = value || '';
							error.value = '';
							note(form, '');
						},
						'expired-callback': function () {
							token.value = '';
						},
						'error-callback': function () {
							token.value = '';
							error.value = 'widget-error';
						}
					});
				} catch (e) {
					form.bcWidget = null;
					error.value = 'widget-render-failed';
				}
			}

			function scan() {
				if (!ready || !lib()) return;
				var selector = cfg.context === 'forms'
					? 'form.elementor-form, form.wpcf7-form, .gform_wrapper form, form.frm-show-form'
					: 'form';
				var forms = document.querySelectorAll(selector);
				for (var i = 0; i < forms.length; i++) {
					if (cfg.context === 'forms' && hasOwnCaptcha(forms[i])) continue;
					render(forms[i]);
				}
			}

			function start() {
				if (ready || !lib()) return;
				ready = true;
				scan();
			}

			window.bcWidgetOnload = start;
			// Another plugin may already have loaded the library without our onload.
			window.addEventListener('load', start);

			// Popups, AJAX-loaded sections, and Gravity's re-render after an error.
			if (cfg.context === 'forms' && window.MutationObserver) {
				new MutationObserver(function () {
					if (scheduled || !ready) return;
					scheduled = true;
					setTimeout(function () {
						scheduled = false;
						scan();
					}, 300);
				}).observe(document.documentElement, {childList: true, subtree: true});
			}

			// Capture phase, so this runs before any form plugin's own handler.
			document.addEventListener('submit', function (e) {
				var form = e.target;
				if (!form || form.tagName !== 'FORM') return;
				// Never rendered or failed to render: let it through, the server decides.
				if (form.bcWidget === undefined || form.bcWidget === null) return;

				// Gravity multi-page "Next"/"Previous" is not the final submission.
				var target = form.querySelector('input[name^="gform_target_page_number_"]');
				if (target && target.value && target.value !== '0') return;

				var token = form.querySelector('input[name="' + cfg.token + '"]');
				var error = form.querySelector('input[name="' + cfg.error + '"]');
				if (token && !token.value && !(error && error.value)) {
					e.preventDefault();
					e.stopPropagation();
					note(form, cfg.msg.required);
					return;
				}

				// wp-login.php reloads the page; only AJAX forms need a fresh check.
				if (cfg.context !== 'forms') return;

				// Tokens are single-use: reset once this dispatch has finished and the
				// form plugin has read the form data.
				setTimeout(function () {
					var api = lib();
					try {
						if (api && typeof api.reset === 'function') api.reset(form.bcWidget);
					} catch (x) {}
					if (token) token.value = '';
				}, 0);
			}, true);
		})();
		</script>
		<?php
	}

	/**
	 * Script URL for the checkbox, with our onload callback and explicit rendering.
	 *
	 * @param string $provider 'recaptcha_v2' or 'turnstile'.
	 * @return string
	 */
	private function widget_script_url( string $provider ): string {
		if ( 'turnstile' === $provider ) {
			return 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=bcWidgetOnload';
		}

		return add_query_arg(
			array(
				'onload' => 'bcWidgetOnload',
				'render' => 'explicit',
				'hl'     => $this->language(),
			),
			'https://www.google.com/recaptcha/api.js'
		);
	}

	/**
	 * reCAPTCHA language code for the current locale.
	 *
	 * @return string
	 */
	private function language(): string {
		$locale   = function_exists( 'determine_locale' ) ? determine_locale() : get_locale();
		$regional = array( 'zh_CN', 'zh_TW', 'zh_HK', 'pt_BR', 'pt_PT', 'fr_CA', 'en_GB', 'es_419', 'de_AT', 'de_CH' );

		if ( in_array( $locale, $regional, true ) ) {
			return str_replace( '_', '-', $locale );
		}

		return strtolower( substr( (string) $locale, 0, 2 ) );
	}

	/* =====================================================================
	 * Invisible reCAPTCHA v3 (contact forms only)
	 * ===================================================================== */

	/**
	 * Render the reCAPTCHA v3 token injection script.
	 *
	 * A single delegated listener on the document in the CAPTURE phase, so it runs
	 * before any form plugin's own submit handler whatever order scripts loaded in.
	 * The form is only held while the library is usable; any timeout or rejection
	 * releases it without a token, and the server rejects it as captcha_missing.
	 * The token is single-use, cleared after each replay so an AJAX form that stays
	 * on the page gets a fresh one.
	 *
	 * @param string $site_key reCAPTCHA v3 site key.
	 */
	private function render_v3_js( string $site_key ): void {
		$config = array(
			'siteKey' => $site_key,
			'token'   => self::TOKEN_FIELD,
			'error'   => self::ERROR_FIELD,
			'skip'    => $this->elementor->client_skip_config(),
		);
		?>
		<script>
		(function() {
			var cfg       = <?php echo wp_json_encode( $config ); ?>;
			var timeoutMs = 10000;

			// Google's snippet defines grecaptcha.ready() synchronously, as a stub
			// that queues the callback before the rest of the library has loaded.
			// Availability only means the stub exists; execute() is checked inside
			// the ready() callback.
			function bcAvailable() {
				return typeof grecaptcha !== 'undefined' &&
					typeof grecaptcha.ready === 'function';
			}

			function bcWarn(message) {
				if (window.console && console.warn) {
					console.warn('bc-security: ' + message);
				}
			}

			function bcSetField(form, name, value) {
				var input = form.querySelector('input[name="' + name + '"]');
				if (!input) {
					if (!value) return;
					input = document.createElement('input');
					input.type = 'hidden';
					input.name = name;
					form.appendChild(input);
				}
				input.value = value;
			}

			// Elementor forms carrying their own configured reCAPTCHA are left to
			// Elementor. Mirrors the server-side step-back exactly.
			function bcHasOwnCaptcha(form) {
				var own = form.querySelector('.elementor-g-recaptcha');
				if (!own) return false;
				return own.getAttribute('data-type') === 'v3' ? !!cfg.skip.v3 : !!cfg.skip.v2;
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

			document.addEventListener('submit', function(e) {
				var form = e.target;
				if (!form || form.tagName !== 'FORM') return;
				if (bcHasOwnCaptcha(form)) return;

				// Replay pass: the token is attached, let every other handler run.
				if (form.bcCaptchaReplay) {
					form.bcCaptchaReplay = false;
					setTimeout(function() {
						bcSetField(form, cfg.token, '');
						bcSetField(form, cfg.error, '');
					}, 0);
					return;
				}

				// A request is already in flight for this form; drop the duplicate.
				if (form.bcCaptchaPending) {
					e.preventDefault();
					e.stopPropagation();
					return;
				}

				// Never hold a form hostage to a library that is not there at all.
				// Per form: one form giving up must not stop checking the others.
				if (form.bcCaptchaGivenUp || !bcAvailable()) return;

				e.preventDefault();
				e.stopPropagation();
				form.bcCaptchaPending = true;

				var done = false;

				function finish(token, code) {
					if (done) return;
					done = true;
					clearTimeout(timer);
					form.bcCaptchaPending = false;
					form.bcCaptchaReplay  = true;
					bcSetField(form, cfg.token, token || '');
					bcSetField(form, cfg.error, token ? '' : (code || ''));
					bcResubmit(form);
				}

				function giveUp(code, message) {
					form.bcCaptchaGivenUp = true;
					bcWarn(message);
					finish('', code);
				}

				var timer = setTimeout(function() {
					giveUp('v3-timeout', 'reCAPTCHA timed out after ' + timeoutMs + 'ms; submitting without a token.');
				}, timeoutMs);

				try {
					grecaptcha.ready(function() {
						if (typeof grecaptcha.execute !== 'function') {
							giveUp('v3-no-execute', 'grecaptcha loaded without execute(); submitting without a token.');
							return;
						}
						try {
							grecaptcha.execute(cfg.siteKey, {action: 'submit'}).then(
								function(token) {
									finish(token, '');
								},
								function() {
									giveUp('v3-rejected', 'reCAPTCHA execute() was rejected; submitting without a token.');
								}
							);
						} catch (err) {
							giveUp('v3-rejected', 'reCAPTCHA execute() threw; submitting without a token.');
						}
					});
				} catch (err) {
					giveUp('v3-rejected', 'grecaptcha.ready() threw; submitting without a token.');
				}
			}, true);
		})();
		</script>
		<?php
	}

	/* =====================================================================
	 * Verification
	 * ===================================================================== */

	/**
	 * Verify the token in the current request against a pair's saved keys.
	 *
	 * Fails closed on a missing, implausible or rejected token. Fails open — with
	 * reason 'captcha_unavailable' — when the provider cannot be reached or reports
	 * a fault with our configuration (only Cloudflare ever reports a bad secret).
	 * Callers decide what "open" means: forms and reset let the request through,
	 * the login escape hatch falls back to the lockout.
	 *
	 * @param string $pair 'main' or 'v3'.
	 * @return array Array with 'success' (bool), 'score' (float) and optionally 'reason' (string).
	 */
	public function verify_pair( string $pair ): array {
		if ( ! $this->is_pair_active( $pair ) ) {
			return array( 'success' => true, 'score' => 1.0 );
		}

		$keys        = CaptchaSettings::pair( $pair );
		$fingerprint = $this->pair_fingerprint( $pair );
		$token       = $this->post_string( self::TOKEN_FIELD );

		if ( '' === $token ) {
			$code = sanitize_key( $this->post_string( self::ERROR_FIELD ) );

			if ( in_array( $code, self::CLIENT_ERROR_CODES, true ) ) {
				$this->health->failure( $pair, $fingerprint, 'client:' . $code );
			}

			return array( 'success' => false, 'score' => 0.0, 'reason' => 'captcha_missing' );
		}

		if ( ! $this->is_plausible_token( $token ) ) {
			return array( 'success' => false, 'score' => 0.0, 'reason' => 'captcha_failed' );
		}

		$response = $this->siteverify( $keys['provider'], $keys['secret'], $token, $this->get_remote_ip(), 5 );
		$parsed   = $this->parse_siteverify( $response, $keys['provider'] );

		if ( null !== $parsed['result'] ) {
			if ( empty( $parsed['result']['success'] ) ) {
				$this->health->failure( $pair, $fingerprint, 'provider' );
			}

			return $parsed['result'];
		}

		// The keys work, even if this visitor's score turns out to be low.
		$this->health->success( $pair, $fingerprint );

		if ( 'v3' === $pair ) {
			$settings  = CaptchaSettings::get();
			$score     = isset( $parsed['body']['score'] ) ? (float) $parsed['body']['score'] : 0.0;
			$threshold = (float) $settings['captcha_score_threshold'];

			if ( $score < $threshold ) {
				return array( 'success' => false, 'score' => $score, 'reason' => 'captcha_score:' . $score );
			}

			return array( 'success' => true, 'score' => $score );
		}

		return array( 'success' => true, 'score' => 1.0 );
	}

	/**
	 * Check a genuine token, produced in the administrator's browser with the typed
	 * site key, against the typed secret. Marks the pair verified only on success.
	 *
	 * @param string $pair     'main' or 'v3'.
	 * @param string $provider Provider slug.
	 * @param string $site     Typed site key.
	 * @param string $secret   Typed secret key.
	 * @param string $token    Token from the probe.
	 * @return array Array with 'ok' (bool) and 'message' (string).
	 */
	public function test_pair( string $pair, string $provider, string $site, string $secret, string $token ): array {
		$allowed = 'v3' === $pair ? array( 'recaptcha_v3' ) : CaptchaSettings::MAIN_PROVIDERS;

		if ( ! in_array( $provider, $allowed, true ) || ! isset( self::$endpoints[ $provider ] ) ) {
			return array( 'ok' => false, 'message' => 'Choose a CAPTCHA provider first.' );
		}

		if ( '' === $site || '' === $secret ) {
			return array( 'ok' => false, 'message' => 'Enter both the site key and the secret key first.' );
		}

		if ( '' === $token || ! $this->is_plausible_token( $token ) ) {
			return array( 'ok' => false, 'message' => 'No test token arrived from your browser. Run the test again.' );
		}

		$name     = 'turnstile' === $provider ? 'Cloudflare' : 'Google';
		$host     = CaptchaSettings::home_host();
		$response = $this->siteverify( $provider, $secret, $token, '', 10 );

		if ( is_wp_error( $response ) ) {
			return array(
				'ok'      => false,
				'message' => "This server couldn't reach {$name} (" . $response->get_error_message() . '). Inconclusive; nothing was changed.',
			);
		}

		$status = (int) wp_remote_retrieve_response_code( $response );

		if ( $status < 200 || $status > 299 ) {
			return array( 'ok' => false, 'message' => "{$name} returned HTTP {$status}. Inconclusive; try again shortly." );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) ) {
			return array( 'ok' => false, 'message' => "{$name} returned a response we couldn't read. Inconclusive; try again shortly." );
		}

		if ( ! empty( $body['success'] ) ) {
			$testing_key = ( isset( $body['hostname'] ) && 'testkey.google.com' === $body['hostname'] )
				|| ! empty( $body['metadata']['result_with_testing_key'] );

			if ( $testing_key ) {
				return array(
					'ok'      => false,
					'message' => "These are {$name}'s public test keys, which accept everything. Use keys created for this site.",
				);
			}

			$has_score = array_key_exists( 'score', $body );

			if ( 'recaptcha_v3' === $provider && ! $has_score ) {
				return array( 'ok' => false, 'message' => 'Google accepted these keys, but they are reCAPTCHA v2 keys. This option needs v3 keys.' );
			}

			if ( 'recaptcha_v2' === $provider && $has_score ) {
				return array( 'ok' => false, 'message' => 'Google accepted these keys, but they are reCAPTCHA v3 keys. This option needs v2 checkbox keys.' );
			}

			$fingerprint = CaptchaSettings::fingerprint( $pair, $provider, $site, $secret );
			$this->verified->mark( $pair, $fingerprint, $host );

			$saved   = hash_equals( $this->pair_fingerprint( $pair ), $fingerprint );
			$message = 'Both keys work on ' . $host . '.' . ( $saved ? ' CAPTCHA is now active for this option.' : ' Save your settings to start using them.' );

			$checked_on = isset( $body['hostname'] ) ? strtolower( (string) $body['hostname'] ) : '';

			if ( '' !== $checked_on && $checked_on !== $host ) {
				$message .= ' Note: the check ran on ' . $checked_on . '; make sure ' . $host . ' is also in the key\'s list of domains.';
			}

			return array( 'ok' => true, 'message' => $message );
		}

		$codes = isset( $body['error-codes'] ) && is_array( $body['error-codes'] )
			? array_map( 'strval', $body['error-codes'] )
			: array();
		$list  = $codes ? ' (' . implode( ', ', $codes ) . ')' : '';

		if ( in_array( 'timeout-or-duplicate', $codes, true ) ) {
			return array( 'ok' => false, 'message' => 'The test token expired before it could be checked. Run the test again.' );
		}

		if ( 'turnstile' === $provider ) {
			if ( array_intersect( $codes, array( 'invalid-input-secret', 'missing-input-secret' ) ) ) {
				return array( 'ok' => false, 'message' => 'Cloudflare rejected the secret key' . $list . '.' );
			}

			return array( 'ok' => false, 'message' => 'Cloudflare issued a token for this site key but would not accept it with this secret key' . $list . '. The secret probably belongs to a different widget.' );
		}

		return array( 'ok' => false, 'message' => 'Google issued a token for this site key but rejected it with this secret key' . $list . '. The secret key is wrong, or it belongs to a different key pair.' );
	}

	/**
	 * Read a string from POST data.
	 *
	 * @param string $key Field name.
	 * @return string
	 */
	private function post_string( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonces are verified by the form or login flow.
		if ( ! isset( $_POST[ $key ] ) || ! is_string( $_POST[ $key ] ) ) {
			return '';
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- As above.
		return sanitize_text_field( wp_unslash( $_POST[ $key ] ) );
	}

	/**
	 * Send a token to a provider's siteverify endpoint.
	 *
	 * @param string $provider Provider slug.
	 * @param string $secret   Secret key.
	 * @param string $token    Token.
	 * @param string $remoteip Visitor IP, or empty to omit.
	 * @param int    $timeout  Seconds.
	 * @return array|\WP_Error
	 */
	private function siteverify( string $provider, string $secret, string $token, string $remoteip, int $timeout ) {
		$body = array(
			'secret'   => $secret,
			'response' => $token,
		);

		if ( '' !== $remoteip ) {
			$body['remoteip'] = $remoteip;
		}

		return wp_remote_post( self::$endpoints[ $provider ], array(
			'body'    => $body,
			'timeout' => $timeout,
		) );
	}

	/**
	 * Check that a token looks like something a CAPTCHA provider could have issued.
	 *
	 * Deliberately permissive: URL-safe and standard base64, dotted Turnstile tokens
	 * and padding all pass. The only job here is to keep obviously hostile input
	 * away from siteverify so a visitor cannot provoke a bad-request, which is
	 * classified as a configuration fault and fails open. If the character class is
	 * ever widened to whitespace or control characters, move 'bad-request' to the
	 * fail-closed side.
	 *
	 * @param string $token Submitted token.
	 * @return bool
	 */
	private function is_plausible_token( string $token ): bool {
		if ( strlen( $token ) > 4096 ) {
			return false;
		}

		return (bool) preg_match( '/^[A-Za-z0-9_\-\.=~+\/]+$/', $token );
	}

	/**
	 * Get the client IP for the provider's optional remoteip parameter.
	 *
	 * Uses IpResolver so the value matches what the rest of the plugin logs. The
	 * parameter is advisory: a spoofed header only degrades the provider's own
	 * risk signal and cannot bypass verification.
	 *
	 * @return string Client IP, or an empty string when unresolved.
	 */
	private function get_remote_ip(): string {
		$ip = $this->ip_resolver->get_client_ip();

		return '0.0.0.0' === $ip ? '' : $ip;
	}

	/**
	 * Decode and classify a siteverify response.
	 *
	 * Configuration and infrastructure faults fail OPEN and are recorded for the
	 * admin notice. Verdicts about the token fail CLOSED.
	 *
	 * @param array|\WP_Error $response Raw wp_remote_post() result.
	 * @param string          $provider Provider slug, for the error record.
	 * @return array Array with 'body' (decoded body, or null) and 'result'
	 *               (a verify_pair() result to return as-is, or null to continue).
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
	 * A transient rather than a log row: this is a configuration problem, not a
	 * submission. Rewritten only when the payload changes, so a flood cannot turn
	 * into one database write per request.
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
}
