<?php
/**
 * Admin page — settings and form submission logs.
 *
 * Provides a "BlueCrocus Security" menu page with two tabs:
 * - Settings: spam protection, CAPTCHA, and password reset protection.
 * - Logs: WP_List_Table-based log viewer with filtering and pagination.
 *
 * Also owns the CAPTCHA admin notices shown on every admin screen.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class AdminPage {

	/**
	 * admin-post action dismissing the one-time 2.3 CAPTCHA notice.
	 */
	const DISMISS_ACTION = 'bc_dismiss_captcha_notice';

	/**
	 * @var FormLogger
	 */
	private $logger;

	/**
	 * @var CaptchaProvider|null
	 */
	private $captcha;

	/**
	 * @var ElementorCaptcha
	 */
	private $elementor;

	/**
	 * Conflict detection result, computed once per request.
	 *
	 * @var array|null
	 */
	private $conflicts = null;

	/**
	 * @param FormLogger            $logger    Form submission logger.
	 * @param CaptchaProvider|null  $captcha   Optional CAPTCHA provider.
	 * @param ElementorCaptcha|null $elementor Elementor reCAPTCHA detection.
	 */
	public function __construct( FormLogger $logger, ?CaptchaProvider $captcha = null, ?ElementorCaptcha $elementor = null ) {
		$this->logger    = $logger;
		$this->captcha   = $captcha;
		$this->elementor = $elementor ? $elementor : new ElementorCaptcha();
	}

	/**
	 * Register WordPress hooks for the admin page.
	 */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_menu_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_init', array( $this, 'handle_clear_logs' ) );
		add_action( 'admin_footer', array( $this, 'render_captcha_admin_js' ) );
		add_action( 'admin_notices', array( $this, 'render_captcha_notices' ) );
		add_action( 'admin_post_' . self::DISMISS_ACTION, array( $this, 'handle_dismiss_migration_notice' ) );
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
					'blocked_keywords' => SpamFilter::DEFAULT_KEYWORDS,
					'blocked_scripts'  => array_keys( SpamFilter::SCRIPTS ),
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

		add_settings_field(
			'blocked_scripts',
			'Blocked Languages',
			array( $this, 'render_blocked_scripts_field' ),
			'bc-security',
			'bc_security_spam_section'
		);

		// CAPTCHA — login & password reset (the main pair).
		add_settings_section(
			'bc_security_captcha_main_section',
			'CAPTCHA — Login & password reset',
			array( $this, 'render_captcha_main_description' ),
			'bc-security'
		);

		add_settings_field(
			'captcha_main_provider',
			'Provider',
			array( $this, 'render_captcha_main_provider_field' ),
			'bc-security',
			'bc_security_captcha_main_section'
		);

		add_settings_field(
			'captcha_main_site_key',
			'Site Key',
			array( $this, 'render_captcha_main_site_key_field' ),
			'bc-security',
			'bc_security_captcha_main_section',
			array( 'label_for' => 'bc_captcha_main_site_key' )
		);

		add_settings_field(
			'captcha_main_secret_key',
			'Secret Key',
			array( $this, 'render_captcha_main_secret_key_field' ),
			'bc-security',
			'bc_security_captcha_main_section',
			array( 'label_for' => 'bc_captcha_main_secret_key' )
		);

		add_settings_field(
			'captcha_main_test',
			'Test Keys',
			array( $this, 'render_captcha_main_test_field' ),
			'bc-security',
			'bc_security_captcha_main_section'
		);

		add_settings_field(
			'captcha_login_challenge',
			'Login Page',
			array( $this, 'render_captcha_login_challenge_field' ),
			'bc-security',
			'bc_security_captcha_main_section'
		);

		add_settings_field(
			'captcha_on_lostpassword',
			'Lost Password Form',
			array( $this, 'render_captcha_lostpassword_field' ),
			'bc-security',
			'bc_security_captcha_main_section'
		);

		// CAPTCHA — contact forms.
		add_settings_section(
			'bc_security_captcha_forms_section',
			'CAPTCHA — Contact forms',
			array( $this, 'render_captcha_forms_description' ),
			'bc-security'
		);

		add_settings_field(
			'captcha_forms_mode',
			'Contact Form CAPTCHA',
			array( $this, 'render_captcha_forms_mode_field' ),
			'bc-security',
			'bc_security_captcha_forms_section',
			array( 'label_for' => 'bc_captcha_forms_mode' )
		);

		add_settings_field(
			'captcha_v3_site_key',
			'reCAPTCHA v3 Site Key',
			array( $this, 'render_captcha_v3_site_key_field' ),
			'bc-security',
			'bc_security_captcha_forms_section',
			array( 'label_for' => 'bc_captcha_v3_site_key', 'class' => 'bc-v3-row' )
		);

		add_settings_field(
			'captcha_v3_secret_key',
			'reCAPTCHA v3 Secret Key',
			array( $this, 'render_captcha_v3_secret_key_field' ),
			'bc-security',
			'bc_security_captcha_forms_section',
			array( 'label_for' => 'bc_captcha_v3_secret_key', 'class' => 'bc-v3-row' )
		);

		add_settings_field(
			'captcha_score_threshold',
			'Score Threshold',
			array( $this, 'render_captcha_threshold_field' ),
			'bc-security',
			'bc_security_captcha_forms_section',
			array( 'label_for' => 'bc_captcha_score_threshold', 'class' => 'bc-v3-row' )
		);

		add_settings_field(
			'captcha_v3_test',
			'Test v3 Keys',
			array( $this, 'render_captcha_v3_test_field' ),
			'bc-security',
			'bc_security_captcha_forms_section',
			array( 'class' => 'bc-v3-row' )
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
	 * Rebuilds the settings from scratch, so every key must be listed here or it is
	 * dropped on save. CAPTCHA keys come from CaptchaSettings::defaults().
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

		// Unticking every language posts no blocked_scripts at all, exactly like a
		// form opened before this field existed. The hidden blocked_scripts_shown
		// tells them apart: without it, keep what is stored rather than switching
		// the language block off.
		if ( isset( $input['blocked_scripts'] ) && is_array( $input['blocked_scripts'] ) ) {
			$scripts = $input['blocked_scripts'];
		} elseif ( ! empty( $input['blocked_scripts_shown'] ) ) {
			$scripts = array();
		} else {
			$stored  = get_option( 'bc_security_settings', array() );
			$scripts = isset( $stored['blocked_scripts'] ) && is_array( $stored['blocked_scripts'] ) ? $stored['blocked_scripts'] : array_keys( SpamFilter::SCRIPTS );
		}

		$sanitized['blocked_scripts'] = array_values( array_intersect( array_keys( SpamFilter::SCRIPTS ), array_filter( $scripts, 'is_string' ) ) );

		// A form without the revision marker was opened before this version was
		// installed and knows nothing of the new CAPTCHA fields: keep what is stored
		// rather than blanking it. captcha_forms_mode is also accepted as a marker,
		// because WordPress runs this callback a second time, on already-sanitized
		// values, when the option is first created.
		$current_form = ( isset( $input['_form_rev'] ) && CaptchaSettings::FORM_REVISION === (string) $input['_form_rev'] )
			|| array_key_exists( 'captcha_forms_mode', $input );

		if ( $current_form ) {
			$provider = isset( $input['captcha_main_provider'] ) ? (string) $input['captcha_main_provider'] : '';
			$mode     = isset( $input['captcha_forms_mode'] ) ? (string) $input['captcha_forms_mode'] : '';

			$sanitized['captcha_main_provider']   = in_array( $provider, CaptchaSettings::MAIN_PROVIDERS, true ) ? $provider : 'recaptcha_v2';
			$sanitized['captcha_main_site_key']   = isset( $input['captcha_main_site_key'] ) ? CaptchaSettings::clean_key( $input['captcha_main_site_key'] ) : '';
			$sanitized['captcha_main_secret_key'] = isset( $input['captcha_main_secret_key'] ) ? CaptchaSettings::clean_key( $input['captcha_main_secret_key'] ) : '';
			$sanitized['captcha_login_challenge'] = ! empty( $input['captcha_login_challenge'] );
			$sanitized['captcha_on_lostpassword'] = ! empty( $input['captcha_on_lostpassword'] );
			$sanitized['captcha_forms_mode']      = in_array( $mode, CaptchaSettings::FORM_MODES, true ) ? $mode : 'off';
			$sanitized['captcha_v3_site_key']     = isset( $input['captcha_v3_site_key'] ) ? CaptchaSettings::clean_key( $input['captcha_v3_site_key'] ) : '';
			$sanitized['captcha_v3_secret_key']   = isset( $input['captcha_v3_secret_key'] ) ? CaptchaSettings::clean_key( $input['captcha_v3_secret_key'] ) : '';

			$threshold = isset( $input['captcha_score_threshold'] ) ? floatval( $input['captcha_score_threshold'] ) : 0.5;
			$sanitized['captcha_score_threshold'] = max( 0.1, min( 0.9, $threshold ) );

			if ( '' !== $sanitized['captcha_main_site_key'] && $sanitized['captcha_main_site_key'] === $sanitized['captcha_v3_site_key'] ) {
				add_settings_error(
					'bc_security_settings',
					'bc_captcha_same_keys',
					'The same site key is entered for login & password reset and for contact forms. Google issues v2 and v3 keys separately, so one of them is the wrong type and will not pass Test Keys.',
					'warning'
				);
			}
		} else {
			$stored = CaptchaSettings::get();

			foreach ( array_keys( CaptchaSettings::defaults() ) as $key ) {
				$sanitized[ $key ] = $stored[ $key ];
			}
		}

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
			'blocked_keywords' => SpamFilter::DEFAULT_KEYWORDS,
		) );

		$checked =! empty( $settings['honeypot_enabled'] ) ? 'checked' : '';
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
			'blocked_keywords' => SpamFilter::DEFAULT_KEYWORDS,
		) );

		$keywords = isset( $settings['blocked_keywords'] ) ? $settings['blocked_keywords'] : SpamFilter::DEFAULT_KEYWORDS;
		$value    = implode( "\n", $keywords );
		?>
		<textarea name="bc_security_settings[blocked_keywords]" rows="10" cols="40" class="large-text"><?php echo esc_textarea( $value ); ?></textarea>
		<p class="description">One keyword or phrase per line. Submissions containing any of these as a whole word or phrase will be blocked. Capital letters and plurals make no difference: "ai agent" also blocks "AI Agents", but "ico" does not block "Nicole".</p>
		<?php
	}

	/**
	 * Render the blocked languages tick boxes.
	 */
	public function render_blocked_scripts_field(): void {
		$settings = get_option( 'bc_security_settings', array() );
		$blocked  = isset( $settings['blocked_scripts'] ) && is_array( $settings['blocked_scripts'] ) ? $settings['blocked_scripts'] : array_keys( SpamFilter::SCRIPTS );
		?>
		<input type="hidden" name="bc_security_settings[blocked_scripts_shown]" value="1" />
		<fieldset>
			<?php foreach ( SpamFilter::SCRIPTS as $slug => $script ) : ?>
				<label>
					<input type="checkbox" name="bc_security_settings[blocked_scripts][]" value="<?php echo esc_attr( $slug ); ?>" <?php checked( in_array( $slug, $blocked, true ) ); ?> />
					<?php echo esc_html( $script['label'] ); ?>
				</label><br />
			<?php endforeach; ?>
		</fieldset>
		<p class="description">Blocks any submission that contains text in a ticked alphabet, even a single word. Untick one if this site has customers who write in that language. Blocked messages can still be read in the Logs tab.</p>
		<?php
	}

	/* =====================================================================
	 * CAPTCHA — login & password reset
	 * ===================================================================== */

	/**
	 * Render the login & password reset CAPTCHA section description.
	 */
	public function render_captcha_main_description(): void {
		?>
		<p>
			An "I'm not a robot" check for the sign-in and "Lost your password?" pages. It needs a free key pair made for this site:
			<strong>Google reCAPTCHA v2</strong> ("I'm not a robot" Checkbox type) from
			<a href="https://www.google.com/recaptcha/admin" target="_blank" rel="noopener noreferrer">google.com/recaptcha/admin</a>,
			or a <strong>Cloudflare Turnstile</strong> widget (Managed mode) from the Cloudflare dashboard.
		</p>
		<p>Keys only take effect once they pass <strong>Test Keys</strong> on this site. Until then the rate limits keep protecting both pages.</p>
		<?php

		$settings  = CaptchaSettings::get();
		$in_use    = ! empty( $settings['captcha_login_challenge'] ) || ! empty( $settings['captcha_on_lostpassword'] );
		$conflicts = $this->conflicts();

		if ( $in_use && $this->captcha && 'no-keys' !== $this->captcha->pair_status( 'main' ) && ! empty( $conflicts['possible'] ) ) {
			echo '<div class="notice notice-info inline"><p>'
				. esc_html( implode( ', ', $conflicts['possible'] ) )
				. ' can also add a CAPTCHA to the login form. If it is switched on there, turn it off in one place or the other.</p></div>';
		}
	}

	/**
	 * Render the main provider dropdown and the status line.
	 */
	public function render_captcha_main_provider_field(): void {
		$settings = CaptchaSettings::get();
		$provider = $settings['captcha_main_provider'];
		?>
		<select name="bc_security_settings[captcha_main_provider]" id="bc_captcha_main_provider" class="bc-captcha-main-input">
			<option value="recaptcha_v2" <?php selected( $provider, 'recaptcha_v2' ); ?>>Google reCAPTCHA v2 ("I'm not a robot" checkbox)</option>
			<option value="turnstile" <?php selected( $provider, 'turnstile' ); ?>>Cloudflare Turnstile</option>
		</select>
		<?php
		$this->render_status_line( 'main' );
	}

	/**
	 * Render the main site key field.
	 */
	public function render_captcha_main_site_key_field(): void {
		$settings = CaptchaSettings::get();
		?>
		<input type="text" id="bc_captcha_main_site_key" name="bc_security_settings[captcha_main_site_key]" value="<?php echo esc_attr( $settings['captcha_main_site_key'] ); ?>" class="regular-text bc-captcha-main-input" autocomplete="off" spellcheck="false" />
		<?php
	}

	/**
	 * Render the main secret key field.
	 */
	public function render_captcha_main_secret_key_field(): void {
		$settings = CaptchaSettings::get();
		?>
		<input type="password" id="bc_captcha_main_secret_key" name="bc_security_settings[captcha_main_secret_key]" value="<?php echo esc_attr( $settings['captcha_main_secret_key'] ); ?>" class="regular-text bc-captcha-main-input" autocomplete="new-password" spellcheck="false" />
		<?php
	}

	/**
	 * Render the main Test Keys button and probe area.
	 */
	public function render_captcha_main_test_field(): void {
		$this->render_test_button( 'main' );
		?>
		<p class="description">Shows the check exactly as visitors will see it. Tick it, and this site confirms both keys with the provider. Nothing is saved by testing: save your settings as usual.</p>
		<?php
	}

	/**
	 * Render the login challenge toggle.
	 */
	public function render_captcha_login_challenge_field(): void {
		$settings = CaptchaSettings::get();
		?>
		<label>
			<input type="checkbox" name="bc_security_settings[captcha_login_challenge]" value="1" <?php checked( ! empty( $settings['captcha_login_challenge'] ) ); ?> />
			Show the check instead of the 15-minute lockout
		</label>
		<p class="description">After 5 failed sign-ins from one connection, WordPress normally blocks that connection for 15 minutes. With this on, it sees the check instead and can keep trying once it's ticked. Everyone else signs in as usual and never sees it. If the provider can't be reached, the lockout applies as before.</p>
		<?php
	}

	/**
	 * Render the lost-password toggle.
	 */
	public function render_captcha_lostpassword_field(): void {
		$settings = CaptchaSettings::get();
		?>
		<label>
			<input type="checkbox" name="bc_security_settings[captcha_on_lostpassword]" value="1" <?php checked( ! empty( $settings['captcha_on_lostpassword'] ) ); ?> />
			Require the check on the "Lost your password?" form
		</label>
		<p class="description">Every reset request must pass the check, which stops bots sending reset emails to your users. Applies to the standard WordPress form only; WooCommerce's My Account reset form keeps the rate limits but shows no check.</p>
		<?php
	}

	/* =====================================================================
	 * CAPTCHA — contact forms
	 * ===================================================================== */

	/**
	 * Render the contact-form CAPTCHA section description.
	 */
	public function render_captcha_forms_description(): void {
		echo '<p>Optional, and off by default: the honeypot and keyword filter above already stop most contact-form spam. Turn this on only for a site that still gets spam through its forms. To use a form plugin\'s own CAPTCHA instead, leave this Off and set it up in the form plugin.</p>';

		$settings  = CaptchaSettings::get();
		$conflicts = $this->conflicts();

		if ( ! empty( $conflicts['stepback'] ) ) {
			echo '<div class="notice notice-info inline"><p><strong>Elementor Pro reCAPTCHA is set up on this site.</strong> Elementor forms that include Elementor\'s own reCAPTCHA field are left to Elementor, so they never get two checks. The honeypot and keyword filter still run on them.</p></div>';
		}

		// Nothing to conflict with while our own contact-form CAPTCHA is off.
		if ( 'off' === $settings['captcha_forms_mode'] ) {
			return;
		}

		if ( ! empty( $conflicts['configured'] ) ) {
			echo '<div class="notice notice-warning inline"><p><strong>Another CAPTCHA is already configured:</strong> '
				. esc_html( implode( ', ', $conflicts['configured'] ) )
				. '. Two CAPTCHAs on one form make submissions fail intermittently and consume double the monthly quota. Turn one of them off.</p></div>';
		}
	}

	/**
	 * Render the contact-form mode dropdown.
	 */
	public function render_captcha_forms_mode_field(): void {
		$settings = CaptchaSettings::get();
		$mode     = $settings['captcha_forms_mode'];
		?>
		<select name="bc_security_settings[captcha_forms_mode]" id="bc_captcha_forms_mode">
			<option value="off" <?php selected( $mode, 'off' ); ?>>Off</option>
			<option value="checkbox" <?php selected( $mode, 'checkbox' ); ?>>Checkbox (uses the login &amp; password reset keys above)</option>
			<option value="v3" <?php selected( $mode, 'v3' ); ?>>Invisible (Google reCAPTCHA v3, its own keys)</option>
		</select>
		<?php
		if ( ! $this->captcha || 'off' === $mode ) {
			return;
		}

		$effective = $this->captcha->forms_mode();

		if ( 'off' === $effective ) {
			$needs = 'checkbox' === $mode ? 'the login &amp; password reset keys above pass' : 'the v3 keys below pass';
			echo '<p class="bc-captcha-status" style="color:#996800;">Not active yet: waiting until ' . $needs . ' Test Keys on ' . esc_html( CaptchaSettings::home_host() ) . '.</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Static text.
		} else {
			echo '<p class="bc-captcha-status" style="color:#008a20;">Active on Elementor Pro, Contact Form 7, Gravity Forms and Formidable forms.</p>';
		}
	}

	/**
	 * Render the v3 site key field.
	 */
	public function render_captcha_v3_site_key_field(): void {
		$settings = CaptchaSettings::get();
		?>
		<input type="text" id="bc_captcha_v3_site_key" name="bc_security_settings[captcha_v3_site_key]" value="<?php echo esc_attr( $settings['captcha_v3_site_key'] ); ?>" class="regular-text bc-captcha-v3-input" autocomplete="off" spellcheck="false" />
		<?php
		$this->render_status_line( 'v3' );
		?>
		<p class="description">reCAPTCHA v3 keys are created separately from v2 keys at <a href="https://www.google.com/recaptcha/admin" target="_blank" rel="noopener noreferrer">google.com/recaptcha/admin</a> (choose "Score based (v3)").</p>
		<?php
	}

	/**
	 * Render the v3 secret key field.
	 */
	public function render_captcha_v3_secret_key_field(): void {
		$settings = CaptchaSettings::get();
		?>
		<input type="password" id="bc_captcha_v3_secret_key" name="bc_security_settings[captcha_v3_secret_key]" value="<?php echo esc_attr( $settings['captcha_v3_secret_key'] ); ?>" class="regular-text bc-captcha-v3-input" autocomplete="new-password" spellcheck="false" />
		<?php
	}

	/**
	 * Render the reCAPTCHA v3 score threshold field.
	 */
	public function render_captcha_threshold_field(): void {
		$settings = CaptchaSettings::get();
		?>
		<input type="number" id="bc_captcha_score_threshold" name="bc_security_settings[captcha_score_threshold]" value="<?php echo esc_attr( $settings['captcha_score_threshold'] ); ?>" min="0.1" max="0.9" step="0.1" class="small-text" />
		<p class="description">Submissions scoring below this are blocked. Default: 0.5 (0.0 = bot, 1.0 = human). There is no second chance for a real visitor who scores low, so avoid raising it.</p>
		<?php
	}

	/**
	 * Render the v3 Test Keys button and probe area.
	 */
	public function render_captcha_v3_test_field(): void {
		$this->render_test_button( 'v3' );
		?>
		<p class="description">Runs reCAPTCHA v3 in your browser with the site key above, then confirms both keys with Google. Nothing is saved by testing.</p>
		<?php
	}

	/**
	 * Render a Test Keys button, its result text and the probe area.
	 *
	 * type="button" is load-bearing: a bare <button> inside the settings form
	 * defaults to submit and would save the settings as a side effect.
	 *
	 * @param string $pair 'main' or 'v3'.
	 */
	private function render_test_button( string $pair ): void {
		?>
		<button type="button" class="button bc-captcha-test" data-pair="<?php echo esc_attr( $pair ); ?>">Test Keys</button>
		<span class="bc-captcha-test-result" id="bc_captcha_test_result_<?php echo esc_attr( $pair ); ?>" role="status" style="margin-left:10px;"></span>
		<div class="bc-captcha-probe" id="bc_captcha_probe_<?php echo esc_attr( $pair ); ?>"></div>
		<?php
	}

	/**
	 * Render a pair's status line.
	 *
	 * @param string $pair 'main' or 'v3'.
	 */
	private function render_status_line( string $pair ): void {
		if ( ! $this->captcha ) {
			return;
		}

		$status = $this->captcha->pair_status( $pair );
		$texts  = $this->status_texts( $pair );
		$text   = $texts[ $status ];

		if ( 'active' === $status ) {
			$time = $this->captcha->verified_time( $pair );

			if ( $time > 0 ) {
				$text .= ' Keys tested ' . wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $time ) . '.';
			}
		}
		?>
		<p class="bc-captcha-status" id="bc_captcha_status_<?php echo esc_attr( $pair ); ?>" data-status="<?php echo esc_attr( $status ); ?>" style="color:<?php echo esc_attr( $this->status_color( $status ) ); ?>;">
			<?php echo esc_html( $text ); ?>
		</p>
		<?php
	}

	/**
	 * Status line texts for a pair.
	 *
	 * @param string $pair 'main' or 'v3'.
	 * @return array Keyed by status.
	 */
	private function status_texts( string $pair ): array {
		$host = CaptchaSettings::home_host();

		return array(
			'active'   => 'Active on ' . $host . '.',
			'untested' => 'Off: these keys haven\'t passed Test Keys on ' . $host . ' yet.',
			'no-keys'  => 'Off: no keys saved.',
			'unsaved'  => 'Unsaved changes: test the keys, then save.',
		);
	}

	/**
	 * Status line colour.
	 *
	 * @param string $status Pair status.
	 * @return string
	 */
	private function status_color( string $status ): string {
		if ( 'active' === $status ) {
			return '#008a20';
		}

		return 'untested' === $status ? '#996800' : '#646970';
	}

	/**
	 * Detected CAPTCHA conflicts, computed once per request.
	 *
	 * @return array
	 */
	private function conflicts(): array {
		if ( null === $this->conflicts ) {
			$this->conflicts = ( new CaptchaConflicts( $this->elementor ) )->detect();
		}

		return $this->conflicts;
	}

	/* =====================================================================
	 * CAPTCHA admin notices
	 * ===================================================================== */

	/**
	 * Render every CAPTCHA notice, on every admin screen.
	 *
	 * Nobody visits a settings page to discover that a security control stopped
	 * working, so these follow the administrator around.
	 */
	public function render_captcha_notices(): void {
		if ( ! current_user_can( 'manage_options' ) || ! $this->captcha ) {
			return;
		}

		$this->render_fault_notice();
		$this->render_untested_notices();
		$this->render_health_notices();
		$this->render_migration_notice();
	}

	/**
	 * Surface the most recent CAPTCHA configuration fault.
	 *
	 * A fault means the provider could not be reached or rejected our own
	 * configuration, so the check is not running.
	 */
	private function render_fault_notice(): void {
		$error = get_transient( CaptchaProvider::ERROR_TRANSIENT );

		if ( ! is_array( $error ) || empty( $error['codes'] ) ) {
			return;
		}

		$codes = implode( ', ', array_map( 'sanitize_text_field', (array) $error['codes'] ) );
		?>
		<div class="notice notice-error">
			<p>
				<strong>BlueCrocus Security:</strong>
				CAPTCHA verification is failing (<code><?php echo esc_html( $codes ); ?></code>).
				While this lasts, contact forms and password reset requests are let through without the check (the other protections still run), and repeated failed sign-ins get the 15-minute lockout instead of the check.
				<a href="<?php echo esc_url( $this->settings_url() ); ?>">Check your CAPTCHA settings</a>.
			</p>
		</div>
		<?php
	}

	/**
	 * Warn when saved keys are switched on for something but have not passed Test Keys.
	 */
	private function render_untested_notices(): void {
		$host = CaptchaSettings::home_host();

		foreach ( array( 'main', 'v3' ) as $pair ) {
			if ( ! $this->pair_in_use( $pair ) || 'untested' !== $this->captcha->pair_status( $pair ) ) {
				continue;
			}

			$what = 'main' === $pair
				? 'The ' . CaptchaSettings::provider_label( $this->captcha->main_provider() ) . ' keys for login &amp; password reset'
				: 'The reCAPTCHA v3 keys for contact forms';
			?>
			<div class="notice notice-warning">
				<p>
					<strong>BlueCrocus Security:</strong>
					<?php echo $what; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Static text and a fixed label. ?>
					haven't passed Test Keys on <?php echo esc_html( $host ); ?>, so that CAPTCHA is off.
					<a href="<?php echo esc_url( $this->settings_url() ); ?>">Run Test Keys</a>.
				</p>
			</div>
			<?php
		}
	}

	/**
	 * Warn when tested keys look like they have stopped working.
	 */
	private function render_health_notices(): void {
		foreach ( array( 'main', 'v3' ) as $pair ) {
			if ( ! $this->pair_in_use( $pair ) ) {
				continue;
			}

			$warning = $this->captcha->health_warning( $pair );

			if ( null === $warning ) {
				continue;
			}

			$label = 'main' === $pair
				? CaptchaSettings::provider_label( $this->captcha->main_provider() )
				: CaptchaSettings::provider_label( 'recaptcha_v3' );
			$since = wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $warning['streak_start'] );
			?>
			<div class="notice notice-error">
				<p>
					<strong>BlueCrocus Security:</strong>
					every <?php echo esc_html( $label ); ?> check since <?php echo esc_html( $since ); ?> has failed, with none succeeding.
					This can be a bot attack, but if the keys were changed or deleted in the provider's console, real visitors are being turned away.
					<a href="<?php echo esc_url( $this->settings_url() ); ?>">Run Test Keys</a> to confirm they still work.
				</p>
			</div>
			<?php
		}
	}

	/**
	 * One-time explanation of the 2.3 CAPTCHA changes, for sites that used CAPTCHA.
	 */
	private function render_migration_notice(): void {
		$legacy = get_option( CaptchaMigration::LEGACY_OPTION, null );

		if ( ! is_array( $legacy ) || ! empty( $legacy['notice_dismissed'] ) ) {
			return;
		}

		$provider = isset( $legacy['provider'] ) ? (string) $legacy['provider'] : 'off';

		// Nothing changed for a site that never switched CAPTCHA on.
		if ( ! in_array( $provider, array( 'recaptcha_v3', 'turnstile' ), true ) ) {
			return;
		}

		$dismiss = wp_nonce_url( admin_url( 'admin-post.php?action=' . self::DISMISS_ACTION ), self::DISMISS_ACTION );
		?>
		<div class="notice notice-info">
			<p><strong>BlueCrocus Security 2.3 changed how CAPTCHA works.</strong></p>
			<ul style="list-style:disc;margin-left:20px;">
				<li>Contact-form CAPTCHA is now <strong>off</strong>. The honeypot and keyword filter still protect your forms. You can switch it back on under "CAPTCHA — Contact forms".</li>
				<?php if ( 'recaptcha_v3' === $provider ) : ?>
					<li>Your reCAPTCHA v3 keys were moved to the contact-form "Invisible" option. They need to pass Test Keys before they are used.</li>
					<li>Login and "Lost your password?" now use a visible "I'm not a robot" checkbox, which needs Google reCAPTCHA v2 keys (v3 keys can't draw a checkbox).</li>
				<?php else : ?>
					<li>Your Cloudflare Turnstile keys are kept for login and "Lost your password?". Run Test Keys to switch them on.</li>
				<?php endif; ?>
				<li>The login and password reset rate limits keep protecting the site in the meantime.</li>
			</ul>
			<p>
				<a href="<?php echo esc_url( $this->settings_url() ); ?>" class="button button-primary">Open CAPTCHA settings</a>
				<a href="<?php echo esc_url( $dismiss ); ?>" class="button">Dismiss</a>
			</p>
		</div>
		<?php
	}

	/**
	 * Dismiss the one-time 2.3 CAPTCHA notice.
	 */
	public function handle_dismiss_migration_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Unauthorized', 'Unauthorized', array( 'response' => 403 ) );
		}

		check_admin_referer( self::DISMISS_ACTION );

		$legacy = get_option( CaptchaMigration::LEGACY_OPTION, null );

		if ( is_array( $legacy ) ) {
			$legacy['notice_dismissed'] = true;
			update_option( CaptchaMigration::LEGACY_OPTION, $legacy, false );
		}

		$back = wp_get_referer();
		wp_safe_redirect( $back ? $back : admin_url() );
		exit;
	}

	/**
	 * Check whether a pair is switched on for anything, whether or not it is active.
	 *
	 * @param string $pair 'main' or 'v3'.
	 * @return bool
	 */
	private function pair_in_use( string $pair ): bool {
		$settings = CaptchaSettings::get();

		if ( 'v3' === $pair ) {
			return 'v3' === $settings['captcha_forms_mode'];
		}

		return ! empty( $settings['captcha_login_challenge'] )
			|| ! empty( $settings['captcha_on_lostpassword'] )
			|| 'checkbox' === $settings['captcha_forms_mode'];
	}

	/**
	 * URL of the settings tab.
	 *
	 * @return string
	 */
	private function settings_url(): string {
		return admin_url( 'admin.php?page=bc-security' );
	}

	/* =====================================================================
	 * Password reset
	 * ===================================================================== */

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

	/* =====================================================================
	 * Admin JavaScript
	 * ===================================================================== */

	/**
	 * Render the settings page script: v3 rows, Test Keys, status lines.
	 *
	 * Test Keys loads a same-origin probe page (CaptchaKeyTest) in an iframe. The
	 * probe draws the provider's check with the typed site key; once it produces a
	 * token, this script sends it to the server with the typed secret. Messages are
	 * only accepted from this site's origin, from the current probe frame, carrying
	 * the current probe's id.
	 */
	public function render_captcha_admin_js(): void {
		$screen = get_current_screen();
		if ( ! $screen || $screen->id !== 'toplevel_page_bc-security' ) {
			return;
		}

		$config = array(
			'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
			'nonce'    => wp_create_nonce( CaptchaKeyTest::TEST_ACTION ),
			'action'   => CaptchaKeyTest::TEST_ACTION,
			'probeUrl' => CaptchaKeyTest::probe_url(),
			'status'   => array(
				'main' => $this->status_texts( 'main' ),
				'v3'   => $this->status_texts( 'v3' ),
			),
			'colors'   => array(
				'active'   => $this->status_color( 'active' ),
				'untested' => $this->status_color( 'untested' ),
				'no-keys'  => $this->status_color( 'no-keys' ),
				'unsaved'  => $this->status_color( 'unsaved' ),
			),
			'msg'      => array(
				'missing'        => 'Enter both the site key and the secret key first.',
				'tick'           => 'Complete the check below.',
				'running'        => 'Running reCAPTCHA v3…',
				'checking'       => 'Checking the keys…',
				'network'        => 'Could not reach this site. Check your connection and try again.',
				'unexpected'     => 'Unexpected response. Reload the page and try again.',
				'expired'        => 'Your session has expired. Reload this page and try again.',
				'bad-input'      => 'That site key doesn\'t look right. Copy it again from the provider\'s console.',
				'widget-error'   => 'The provider refused this site key. It may be the wrong type (for example a v3 key where a v2 checkbox key is needed), or this domain isn\'t on the key\'s list of domains.',
				'execute-rejected' => 'Google refused this site key. Make sure it is a reCAPTCHA v3 key and this domain is on its list of domains.',
				'script-blocked' => 'Your browser couldn\'t load the provider\'s script. An ad blocker or privacy extension may be blocking it: allow it for this site and try again.',
				'timeout-v3'     => 'Google didn\'t produce a token within 15 seconds. Make sure this is a reCAPTCHA v3 key and this domain is on its list of domains.',
				'timeout'        => 'The check wasn\'t completed in time. Run the test again.',
			),
		);
		?>
		<script>
		(function () {
			var cfg = <?php echo wp_json_encode( $config ); ?>;
			var RED = '#d63638';
			var GREEN = '#008a20';

			function byId(id) {
				return document.getElementById(id);
			}

			// Contact-form v3 rows show only in Invisible mode.
			var mode = byId('bc_captcha_forms_mode');
			function toggleRows() {
				var rows = document.querySelectorAll('tr.bc-v3-row');
				for (var i = 0; i < rows.length; i++) {
					rows[i].style.display = (mode && mode.value === 'v3') ? '' : 'none';
				}
			}
			if (mode) {
				mode.addEventListener('change', toggleRows);
				toggleRows();
			}

			function setStatus(pair, status) {
				var line = byId('bc_captcha_status_' + pair);
				if (!line || !cfg.status[pair][status]) return;
				line.textContent = cfg.status[pair][status];
				line.style.color = cfg.colors[status] || '';
				line.setAttribute('data-status', status);
			}

			function watchInputs(selector, pair) {
				var inputs = document.querySelectorAll(selector);
				for (var i = 0; i < inputs.length; i++) {
					inputs[i].addEventListener('input', function () { setStatus(pair, 'unsaved'); });
					inputs[i].addEventListener('change', function () { setStatus(pair, 'unsaved'); });
				}
			}
			watchInputs('.bc-captcha-main-input', 'main');
			watchInputs('.bc-captcha-v3-input', 'v3');

			function fields(pair) {
				if (pair === 'v3') {
					return {provider: 'recaptcha_v3', site: byId('bc_captcha_v3_site_key'), secret: byId('bc_captcha_v3_secret_key')};
				}
				var select = byId('bc_captcha_main_provider');
				return {provider: select ? select.value : '', site: byId('bc_captcha_main_site_key'), secret: byId('bc_captcha_main_secret_key')};
			}

			function clean(input) {
				return input ? input.value.replace(/\s+/g, '') : '';
			}

			function say(el, text, color) {
				el.textContent = text;
				el.style.color = color || '';
			}

			var active = null;

			function stop(run) {
				if (!run) return;
				if (run.frame && run.frame.parentNode) run.frame.parentNode.removeChild(run.frame);
				if (active === run) active = null;
			}

			function start(button) {
				var pair = button.getAttribute('data-pair') === 'v3' ? 'v3' : 'main';
				var f = fields(pair);
				var site = clean(f.site);
				var secret = clean(f.secret);
				var result = byId('bc_captcha_test_result_' + pair);
				var area = byId('bc_captcha_probe_' + pair);
				if (!result || !area) return;

				// One test at a time.
				if (active) {
					active.button.disabled = false;
					stop(active);
				}

				if (!site || !secret) {
					say(result, cfg.msg.missing, RED);
					return;
				}

				var id = 'p' + Math.random().toString(36).slice(2) + Date.now().toString(36);
				var frame = document.createElement('iframe');
				frame.title = 'CAPTCHA key test';
				frame.style.cssText = 'display:block;border:0;width:100%;max-width:420px;height:90px;margin-top:8px;background:transparent;';
				frame.src = cfg.probeUrl
					+ '&pair=' + encodeURIComponent(pair)
					+ '&provider=' + encodeURIComponent(f.provider)
					+ '&site_key=' + encodeURIComponent(site)
					+ '&probe=' + encodeURIComponent(id);

				active = {id: id, pair: pair, provider: f.provider, site: site, secret: secret, frame: frame, button: button, result: result};
				button.disabled = true;
				say(result, pair === 'v3' ? cfg.msg.running : cfg.msg.tick, '');
				area.appendChild(frame);
			}

			function check(run, token) {
				stop(run);
				say(run.result, cfg.msg.checking, '');

				var body = new URLSearchParams();
				body.append('action', cfg.action);
				body.append('nonce', cfg.nonce);
				body.append('pair', run.pair);
				body.append('provider', run.provider);
				body.append('site_key', run.site);
				body.append('secret', run.secret);
				body.append('token', token);

				fetch(cfg.ajaxUrl, {
					method: 'POST',
					credentials: 'same-origin',
					headers: {'Content-Type': 'application/x-www-form-urlencoded'},
					body: body.toString()
				}).then(function (r) {
					return r.json();
				}).then(function (json) {
					var data = (json && json.data) ? json.data : {};
					say(run.result, data.message || cfg.msg.unexpected, (json && json.success) ? GREEN : RED);
					if (json && json.success && data.status) setStatus(run.pair, data.status);
				}).catch(function () {
					say(run.result, cfg.msg.network, RED);
				}).then(function () {
					run.button.disabled = false;
				});
			}

			var buttons = document.querySelectorAll('.bc-captcha-test');
			for (var i = 0; i < buttons.length; i++) {
				buttons[i].addEventListener('click', function (e) {
					start(e.currentTarget);
				});
			}

			window.addEventListener('message', function (e) {
				var run = active;
				if (!run || e.origin !== window.location.origin || e.source !== run.frame.contentWindow) return;
				var d = e.data;
				if (!d || typeof d !== 'object' || d.bcProbe !== run.id) return;

				if (d.type === 'size') {
					var h = parseInt(d.height, 10) || 0;
					run.frame.style.height = Math.min(Math.max(h, 90), 700) + 'px';
					return;
				}
				if (d.type === 'ready') return;

				if (d.type === 'token' && typeof d.token === 'string' && d.token) {
					check(run, d.token);
					return;
				}

				var text = cfg.msg.unexpected;
				if (d.type === 'script-blocked') {
					text = cfg.msg['script-blocked'];
				} else if (d.type === 'timeout') {
					text = run.pair === 'v3' ? cfg.msg['timeout-v3'] : cfg.msg.timeout;
				} else if (d.type === 'error' && cfg.msg[d.code]) {
					text = cfg.msg[d.code];
				}
				say(run.result, text, RED);
				run.button.disabled = false;
				stop(run);
			});
		})();
		</script>
		<?php
	}

	/* =====================================================================
	 * Page
	 * ===================================================================== */

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
			?>
			<input type="hidden" name="bc_security_settings[_form_rev]" value="<?php echo esc_attr( CaptchaSettings::FORM_REVISION ); ?>" />
			<?php
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
