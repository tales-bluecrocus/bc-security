<?php
/**
 * Admin page — settings and form submission logs.
 *
 * Provides a "BlueCrocus Security" menu page with two tabs:
 * - Settings: honeypot toggle and blocked keywords textarea.
 * - Logs: WP_List_Table-based log viewer with filtering and pagination.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class AdminPage {

	/**
	 * @var FormLogger
	 */
	private $logger;

	/**
	 * Default blocked keywords (used to populate the textarea on first load).
	 *
	 * @var array
	 */
	private $default_keywords = array(
		'seo',
		'marketing',
		'bitcoin',
		'crypto',
		'casino',
		'viagra',
		'forex',
		'backlinks',
		'link building',
		'guest post',
		'cbd',
		'diet pills',
		'weight loss',
	);

	/**
	 * @var CaptchaProvider|null
	 */
	private $captcha;

	/**
	 * @param FormLogger           $logger  Form submission logger.
	 * @param CaptchaProvider|null $captcha Optional CAPTCHA provider.
	 */
	public function __construct( FormLogger $logger, ?CaptchaProvider $captcha = null ) {
		$this->logger  = $logger;
		$this->captcha = $captcha;
	}

	/**
	 * Register WordPress hooks for the admin page.
	 */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_menu_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_init', array( $this, 'handle_clear_logs' ) );
		add_action( 'admin_footer', array( $this, 'render_captcha_admin_js' ) );
		add_action( 'admin_notices', array( $this, 'render_captcha_error_notice' ) );
		add_action( 'wp_ajax_bc_test_captcha', array( $this, 'handle_test_captcha' ) );
	}

	/**
	 * Add the "BlueCrocus Security" top-level admin menu page.
	 */
	public function add_menu_page(): void {
		add_menu_page(
			'BlueCrocus Security',
			'BlueCrocus Security',
			'manage_options',
			'bc-security',
			array( $this, 'render_page' ),
			'dashicons-shield-alt',
			81
		);
	}

	/**
	 * Register settings using the WordPress Settings API.
	 */
	public function register_settings(): void {
		register_setting(
			'bc_security_settings_group',
			'bc_security_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_settings' ),
				'default'           => array(
					'honeypot_enabled' => true,
					'blocked_keywords' => $this->default_keywords,
				),
			)
		);

		add_settings_section(
			'bc_security_spam_section',
			'Spam Protection',
			array( $this, 'render_section_description' ),
			'bc-security'
		);

		add_settings_field(
			'honeypot_enabled',
			'Honeypot Protection',
			array( $this, 'render_honeypot_field' ),
			'bc-security',
			'bc_security_spam_section'
		);

		add_settings_field(
			'blocked_keywords',
			'Blocked Keywords',
			array( $this, 'render_keywords_field' ),
			'bc-security',
			'bc_security_spam_section'
		);

		add_settings_section(
			'bc_security_captcha_section',
			'CAPTCHA Protection',
			array( $this, 'render_captcha_section_description' ),
			'bc-security'
		);

		add_settings_field(
			'captcha_provider',
			'CAPTCHA Provider',
			array( $this, 'render_captcha_provider_field' ),
			'bc-security',
			'bc_security_captcha_section'
		);

		add_settings_field(
			'captcha_site_key',
			'Site Key',
			array( $this, 'render_captcha_site_key_field' ),
			'bc-security',
			'bc_security_captcha_section'
		);

		add_settings_field(
			'captcha_secret_key',
			'Secret Key',
			array( $this, 'render_captcha_secret_key_field' ),
			'bc-security',
			'bc_security_captcha_section'
		);

		add_settings_field(
			'captcha_score_threshold',
			'Score Threshold',
			array( $this, 'render_captcha_threshold_field' ),
			'bc-security',
			'bc_security_captcha_section'
		);

		add_settings_field(
			'captcha_on_login',
			'Protect Login Page',
			array( $this, 'render_captcha_login_field' ),
			'bc-security',
			'bc_security_captcha_section'
		);

		add_settings_field(
			'captcha_on_lostpassword',
			'Protect Lost Password Form',
			array( $this, 'render_captcha_lostpassword_field' ),
			'bc-security',
			'bc_security_captcha_section'
		);

		add_settings_field(
			'captcha_test',
			'Test CAPTCHA Keys',
			array( $this, 'render_captcha_test_field' ),
			'bc-security',
			'bc_security_captcha_section'
		);

		add_settings_section(
			'bc_security_pwreset_section',
			'Password Reset Protection',
			array( $this, 'render_pwreset_section_description' ),
			'bc-security'
		);

		add_settings_field(
			'pwreset_protection',
			'Rate Limit Reset Requests',
			array( $this, 'render_pwreset_protection_field' ),
			'bc-security',
			'bc_security_pwreset_section'
		);

		add_settings_field(
			'pwreset_generic_response',
			'Hide Account Existence',
			array( $this, 'render_pwreset_generic_field' ),
			'bc-security',
			'bc_security_pwreset_section'
		);
	}

	/**
	 * Sanitize settings before saving.
	 *
	 * @param array $input Raw input from the settings form.
	 * @return array Sanitized settings.
	 */
	public function sanitize_settings( $input ): array {
		if ( ! is_array( $input ) ) {
			$input = array();
		}

		$sanitized = array();

		$sanitized['honeypot_enabled'] = ! empty( $input['honeypot_enabled'] );

		$keywords_raw = isset( $input['blocked_keywords'] ) ? $input['blocked_keywords'] : '';
		$keywords     = is_array( $keywords_raw ) ? $keywords_raw : array_map( 'trim', explode( "\n", $keywords_raw ) );
		$keywords     = array_filter( $keywords, function ( $keyword ) {
			return $keyword !== '';
		} );
		$keywords     = array_map( 'sanitize_text_field', $keywords );
		$keywords     = array_values( $keywords );

		$sanitized['blocked_keywords'] = $keywords;

		$valid_providers = array( 'off', 'recaptcha_v3', 'turnstile' );
		$sanitized['captcha_provider'] = isset( $input['captcha_provider'] ) && in_array( $input['captcha_provider'], $valid_providers, true )
			? $input['captcha_provider']
			: 'off';

		$sanitized['captcha_site_key']   = isset( $input['captcha_site_key'] ) ? sanitize_text_field( $input['captcha_site_key'] ) : '';
		$sanitized['captcha_secret_key'] = isset( $input['captcha_secret_key'] ) ? sanitize_text_field( $input['captcha_secret_key'] ) : '';

		$threshold = isset( $input['captcha_score_threshold'] ) ? floatval( $input['captcha_score_threshold'] ) : 0.5;
		$sanitized['captcha_score_threshold'] = max( 0.1, min( 0.9, $threshold ) );

		$sanitized['captcha_on_login']        = ! empty( $input['captcha_on_login'] );
		$sanitized['captcha_on_lostpassword'] = ! empty( $input['captcha_on_lostpassword'] );

		$sanitized['pwreset_protection']       = ! empty( $input['pwreset_protection'] );
		$sanitized['pwreset_generic_response'] = ! empty( $input['pwreset_generic_response'] );

		// Any recorded CAPTCHA fault refers to the configuration being replaced.
		delete_transient( CaptchaProvider::ERROR_TRANSIENT );

		return $sanitized;
	}

	/**
	 * Render the spam protection section description.
	 */
	public function render_section_description(): void {
		echo '<p>Configure spam protection for contact forms. These settings apply to Elementor Pro, Contact Form 7, Gravity Forms, and Formidable Forms.</p>';
	}

	/**
	 * Render the honeypot toggle checkbox.
	 */
	public function render_honeypot_field(): void {
		$settings = get_option( 'bc_security_settings', array(
			'honeypot_enabled' => true,
			'blocked_keywords' => $this->default_keywords,
		) );

		$checked = ! empty( $settings['honeypot_enabled'] ) ? 'checked' : '';
		?>
		<label>
			<input type="checkbox" name="bc_security_settings[honeypot_enabled]" value="1" <?php echo $checked; ?> />
			Enable honeypot field on all forms
		</label>
		<p class="description">Adds a hidden field to forms that only bots will fill in. Submissions with a filled honeypot are automatically blocked.</p>
		<?php
	}

	/**
	 * Render the blocked keywords textarea.
	 */
	public function render_keywords_field(): void {
		$settings = get_option( 'bc_security_settings', array(
			'honeypot_enabled' => true,
			'blocked_keywords' => $this->default_keywords,
		) );

		$keywords = isset( $settings['blocked_keywords'] ) ? $settings['blocked_keywords'] : $this->default_keywords;
		$value    = implode( "\n", $keywords );
		?>
		<textarea name="bc_security_settings[blocked_keywords]" rows="10" cols="40" class="large-text"><?php echo esc_textarea( $value ); ?></textarea>
		<p class="description">One keyword or phrase per line. Submissions containing any of these words (case-insensitive) will be blocked.</p>
		<?php
	}

	/**
	 * Render the CAPTCHA section description.
	 */
	public function render_captcha_section_description(): void {
		echo '<p>Add CAPTCHA verification to forms and login. Requires a free API key from Google reCAPTCHA or Cloudflare Turnstile.</p>';

		$settings = $this->get_captcha_settings();

		// Nothing to conflict with while our own CAPTCHA is off.
		if ( $settings['captcha_provider'] === 'off' ) {
			return;
		}

		$conflicts = ( new CaptchaConflicts() )->detect();

		if ( ! empty( $conflicts['configured'] ) ) {
			echo '<div class="notice notice-warning inline"><p><strong>Another CAPTCHA is already configured:</strong> '
				. esc_html( implode( ', ', $conflicts['configured'] ) )
				. '. Two CAPTCHAs on one form make submissions fail intermittently and consume double the monthly quota. Turn one of them off.</p></div>';
		}

		if ( ! empty( $conflicts['possible'] ) ) {
			echo '<div class="notice notice-info inline"><p>'
				. esc_html( implode( ', ', $conflicts['possible'] ) )
				. ' can also add a CAPTCHA to the login form. If it is enabled there, disable it in one place or the other.</p></div>';
		}
	}

	/**
	 * Render the CAPTCHA provider dropdown.
	 */
	public function render_captcha_provider_field(): void {
		$settings = $this->get_captcha_settings();
		$provider = $settings['captcha_provider'];
		?>
		<select name="bc_security_settings[captcha_provider]" id="bc_captcha_provider">
			<option value="off" <?php selected( $provider, 'off' ); ?>>Off</option>
			<option value="recaptcha_v3" <?php selected( $provider, 'recaptcha_v3' ); ?>>reCAPTCHA v3</option>
			<option value="turnstile" <?php selected( $provider, 'turnstile' ); ?>>Cloudflare Turnstile</option>
		</select>
		<?php
	}

	/**
	 * Render the CAPTCHA site key field.
	 */
	public function render_captcha_site_key_field(): void {
		$settings = $this->get_captcha_settings();
		?>
		<input type="text" id="bc_captcha_site_key" name="bc_security_settings[captcha_site_key]" value="<?php echo esc_attr( $settings['captcha_site_key'] ); ?>" class="regular-text bc-captcha-field" />
		<?php
	}

	/**
	 * Render the CAPTCHA secret key field.
	 */
	public function render_captcha_secret_key_field(): void {
		$settings = $this->get_captcha_settings();
		?>
		<input type="password" id="bc_captcha_secret_key" name="bc_security_settings[captcha_secret_key]" value="<?php echo esc_attr( $settings['captcha_secret_key'] ); ?>" class="regular-text bc-captcha-field" />
		<?php
	}

	/**
	 * Render the reCAPTCHA score threshold field.
	 */
	public function render_captcha_threshold_field(): void {
		$settings = $this->get_captcha_settings();
		?>
		<input type="number" name="bc_security_settings[captcha_score_threshold]" value="<?php echo esc_attr( $settings['captcha_score_threshold'] ); ?>" min="0.1" max="0.9" step="0.1" class="small-text bc-captcha-recaptcha-field" />
		<p class="description">Submissions scoring below this threshold are blocked. Default: 0.5 (0.0 = bot, 1.0 = human).</p>
		<?php
	}

	/**
	 * Render the CAPTCHA login protection checkbox.
	 */
	public function render_captcha_login_field(): void {
		$settings = $this->get_captcha_settings();
		$checked  = ! empty( $settings['captcha_on_login'] ) ? 'checked' : '';
		?>
		<label>
			<input type="checkbox" name="bc_security_settings[captcha_on_login]" value="1" <?php echo $checked; ?> class="bc-captcha-field" />
			Enable CAPTCHA on wp-login.php
		</label>
		<?php
	}

	/**
	 * Render the CAPTCHA lost-password protection checkbox.
	 */
	public function render_captcha_lostpassword_field(): void {
		$settings = $this->get_captcha_settings();
		$checked  = ! empty( $settings['captcha_on_lostpassword'] ) ? 'checked' : '';
		?>
		<label>
			<input type="checkbox" name="bc_security_settings[captcha_on_lostpassword]" value="1" <?php echo $checked; ?> class="bc-captcha-field" />
			Enable CAPTCHA on the "Lost your password?" form
		</label>
		<p class="description">Verifies reset requests before an email is generated. Safer to enable than login protection: if CAPTCHA misfires here, password recovery is blocked, whereas on the login form nobody can sign in at all.</p>
		<?php
	}

	/**
	 * Render the "Test CAPTCHA Keys" button and result area.
	 *
	 * type="button" is load-bearing: a bare <button> inside the settings form
	 * defaults to submit and would save the settings as a side effect.
	 */
	public function render_captcha_test_field(): void {
		?>
		<button type="button" class="button bc-captcha-field" id="bc_captcha_test_button">Test Keys</button>
		<span id="bc_captcha_test_result" style="margin-left:10px;"></span>
		<p class="description bc-captcha-field">Checks the secret key against the provider without saving. Worth running before you rely on CAPTCHA on a site, and again if forms start behaving oddly.</p>
		<?php
	}

	/**
	 * Handle the AJAX key test.
	 *
	 * Tests the values currently in the form, not the saved ones, so a pasted key
	 * can be checked before committing to it. Saves nothing.
	 */
	public function handle_test_captcha(): void {
		check_ajax_referer( 'bc_test_captcha', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Insufficient permissions.' ), 403 );
		}

		if ( ! $this->captcha ) {
			wp_send_json_error( array( 'message' => 'CAPTCHA provider unavailable.' ) );
		}

		$provider = isset( $_POST['provider'] ) ? sanitize_text_field( wp_unslash( $_POST['provider'] ) ) : '';
		$secret   = isset( $_POST['secret'] ) ? sanitize_text_field( wp_unslash( $_POST['secret'] ) ) : '';

		$result = $this->captcha->test_keys( $provider, $secret );

		if ( ! empty( $result['ok'] ) ) {
			wp_send_json_success( array( 'message' => $result['message'] ) );
		}

		wp_send_json_error( array( 'message' => $result['message'] ) );
	}

	/**
	 * Surface the most recent CAPTCHA configuration fault.
	 *
	 * A fault means verify() is failing open, so the CAPTCHA layer is silently
	 * doing nothing. Shown on every admin screen because nobody visits a settings
	 * page to discover that a security control stopped working.
	 */
	public function render_captcha_error_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$error = get_transient( CaptchaProvider::ERROR_TRANSIENT );

		if ( ! is_array( $error ) || empty( $error['codes'] ) ) {
			return;
		}

		$codes = implode( ', ', array_map( 'sanitize_text_field', (array) $error['codes'] ) );
		$url   = admin_url( 'admin.php?page=bc-security' );
		?>
		<div class="notice notice-error">
			<p>
				<strong>BlueCrocus Security:</strong>
				CAPTCHA verification is failing (<code><?php echo esc_html( $codes ); ?></code>).
				Submissions are being allowed through unchecked until this is fixed.
				<a href="<?php echo esc_url( $url ); ?>">Check your CAPTCHA settings</a>.
			</p>
		</div>
		<?php
	}

	/**
	 * Render the password reset section description.
	 */
	public function render_pwreset_section_description(): void {
		echo '<p>Protects the "Lost your password?" form against automated abuse. Bots submitting reset requests are throttled, and each account can only be sent one reset email every 15 minutes.</p>';
	}

	/**
	 * Render the reset rate limiting toggle checkbox.
	 */
	public function render_pwreset_protection_field(): void {
		$settings = $this->get_pwreset_settings();
		$checked  = ! empty( $settings['pwreset_protection'] ) ? 'checked' : '';
		?>
		<label>
			<input type="checkbox" name="bc_security_settings[pwreset_protection]" value="1" <?php echo $checked; ?> />
			Limit password reset requests
		</label>
		<p class="description">Throttles an IP after 3 reset requests, and sends at most one reset email per account every 15 minutes. Blocked attempts appear in the Logs tab.</p>
		<?php
	}

	/**
	 * Render the generic response toggle checkbox.
	 */
	public function render_pwreset_generic_field(): void {
		$settings = $this->get_pwreset_settings();
		$checked  = ! empty( $settings['pwreset_generic_response'] ) ? 'checked' : '';
		?>
		<label>
			<input type="checkbox" name="bc_security_settings[pwreset_generic_response]" value="1" <?php echo $checked; ?> />
			Always show the same confirmation message
		</label>
		<p class="description">Stops the reset form from revealing whether an account exists. Without this, WordPress replies "There is no account with that username or email address", which bots use to confirm valid accounts.</p>
		<?php
	}

	/**
	 * Get password reset settings with defaults.
	 *
	 * @return array Password reset settings.
	 */
	private function get_pwreset_settings(): array {
		$settings = get_option( 'bc_security_settings', array() );
		return wp_parse_args( $settings, array(
			'pwreset_protection'       => true,
			'pwreset_generic_response' => true,
		) );
	}

	/**
	 * Get CAPTCHA-related settings with defaults.
	 *
	 * @return array CAPTCHA settings.
	 */
	private function get_captcha_settings(): array {
		$settings = get_option( 'bc_security_settings', array() );
		return wp_parse_args( $settings, array(
			'captcha_provider'        => 'off',
			'captcha_site_key'        => '',
			'captcha_secret_key'      => '',
			'captcha_score_threshold' => 0.5,
			'captcha_on_login'        => false,
			'captcha_on_lostpassword' => false,
		) );
	}

	/**
	 * Render JavaScript to show/hide CAPTCHA fields based on provider selection.
	 */
	public function render_captcha_admin_js(): void {
		$screen = get_current_screen();
		if ( ! $screen || $screen->id !== 'toplevel_page_bc-security' ) {
			return;
		}
		?>
		<script>
		(function() {
			var provider = document.getElementById('bc_captcha_provider');
			if (!provider) return;

			function toggle() {
				var val = provider.value;
				var captchaFields = document.querySelectorAll('.bc-captcha-field');
				var recaptchaFields = document.querySelectorAll('.bc-captcha-recaptcha-field');

				for (var i = 0; i < captchaFields.length; i++) {
					captchaFields[i].closest('tr').style.display = (val === 'off') ? 'none' : '';
				}
				for (var j = 0; j < recaptchaFields.length; j++) {
					recaptchaFields[j].closest('tr').style.display = (val === 'recaptcha_v3') ? '' : 'none';
				}
			}

			provider.addEventListener('change', toggle);
			toggle();

			var testButton = document.getElementById('bc_captcha_test_button');
			var testResult = document.getElementById('bc_captcha_test_result');
			if (!testButton || !testResult) return;

			testButton.addEventListener('click', function() {
				var secretField = document.getElementById('bc_captcha_secret_key');

				testButton.disabled = true;
				testResult.textContent = 'Testing…';
				testResult.style.color = '';

				var body = new URLSearchParams();
				body.append('action', 'bc_test_captcha');
				body.append('nonce', <?php echo wp_json_encode( wp_create_nonce( 'bc_test_captcha' ) ); ?>);
				body.append('provider', provider.value);
				body.append('secret', secretField ? secretField.value : '');

				fetch(<?php echo wp_json_encode( admin_url( 'admin-ajax.php' ) ); ?>, {
					method: 'POST',
					credentials: 'same-origin',
					headers: {'Content-Type': 'application/x-www-form-urlencoded'},
					body: body.toString()
				}).then(function(r) {
					return r.json();
				}).then(function(json) {
					var ok = json && json.success;
					var message = (json && json.data && json.data.message) ? json.data.message : 'Unexpected response.';
					testResult.textContent = message;
					testResult.style.color = ok ? '#008a20' : '#d63638';
				}).catch(function() {
					testResult.textContent = 'Could not reach the site. Check your connection and try again.';
					testResult.style.color = '#d63638';
				}).then(function() {
					testButton.disabled = false;
				});
			});
		})();
		</script>
		<?php
	}

	/**
	 * Handle the Clear Logs action.
	 */
	public function handle_clear_logs(): void {
		if ( ! isset( $_GET['action'] ) || $_GET['action'] !== 'bc_clear_logs' ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Unauthorized', 'Unauthorized', array( 'response' => 403 ) );
		}

		if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'bc_clear_logs' ) ) {
			wp_die( 'Invalid nonce', 'Forbidden', array( 'response' => 403 ) );
		}

		$this->logger->clear_logs();

		wp_safe_redirect( admin_url( 'admin.php?page=bc-security&tab=logs&cleared=1' ) );
		exit;
	}

	/**
	 * Render the admin page with tab navigation.
	 */
	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$current_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'settings';
		?>
		<div class="wrap">
			<h1>BlueCrocus Security</h1>

			<nav class="nav-tab-wrapper">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=bc-security&tab=settings' ) ); ?>" class="nav-tab <?php echo $current_tab === 'settings' ? 'nav-tab-active' : ''; ?>">
					Settings
				</a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=bc-security&tab=logs' ) ); ?>" class="nav-tab <?php echo $current_tab === 'logs' ? 'nav-tab-active' : ''; ?>">
					Form Logs
				</a>
			</nav>

			<div class="tab-content" style="margin-top: 15px;">
				<?php
				if ( $current_tab === 'logs' ) {
					$this->render_logs_tab();
				} else {
					$this->render_settings_tab();
				}
				?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Settings tab content.
	 */
	private function render_settings_tab(): void {
		?>
		<form method="post" action="options.php">
			<?php
			settings_fields( 'bc_security_settings_group' );
			do_settings_sections( 'bc-security' );
			submit_button( 'Save Settings' );
			?>
		</form>
		<?php
	}

	/**
	 * Render the Logs tab content with log table, filters, and clear button.
	 */
	private function render_logs_tab(): void {
		if ( isset( $_GET['cleared'] ) && $_GET['cleared'] === '1' ) {
			echo '<div class="notice notice-success is-dismissible"><p>All logs have been cleared.</p></div>';
		}

		$table = new LogsTable( $this->logger );
		$table->prepare_items();

		$clear_url = wp_nonce_url(
			admin_url( 'admin.php?page=bc-security&tab=logs&action=bc_clear_logs' ),
			'bc_clear_logs'
		);
		?>
		<form method="get">
			<input type="hidden" name="page" value="bc-security" />
			<input type="hidden" name="tab" value="logs" />
			<?php
			$table->search_box( 'Search IP / Reason', 'bc-log-search' );
			$table->display();
			?>
		</form>

		<p style="margin-top: 15px;">
			<a href="<?php echo esc_url( $clear_url ); ?>"
			   class="button button-secondary"
			   onclick="return confirm('Are you sure you want to delete all form logs? This action cannot be undone.');">
				Clear All Logs
			</a>
		</p>
		<?php
	}
}
