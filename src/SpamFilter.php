<?php
/**
 * Spam filter — honeypot and keyword-based spam blocking for contact forms.
 *
 * Hooks into Elementor Pro, Contact Form 7, Gravity Forms, and Formidable Forms
 * to inject a honeypot field and check submissions against a blocked keywords list.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class SpamFilter {

	/**
	 * @var IpResolver
	 */
	private $ip_resolver;

	/**
	 * @var FormLogger
	 */
	private $logger;

	/**
	 * @var CaptchaProvider
	 */
	private $captcha;

	/**
	 * Default blocked keywords used when settings have not been saved yet.
	 *
	 * @var array
	 */
	private $default_keywords = array(
		// SEO & Digital Marketing.
		'seo',
		'search engine optimization',
		'rank your website',
		'first page of google',
		'google ranking',
		'backlinks',
		'link building',
		'domain authority',
		'organic traffic',
		'keyword research',
		'content marketing',
		'digital marketing agency',
		'increase your traffic',
		'boost your rankings',
		'guest post',
		'white hat seo',
		'black hat seo',
		'off-page seo',
		'on-page seo',
		'local seo',
		'guaranteed rankings',
		'#1 on google',
		'drive traffic to your website',
		'web traffic',
		'marketing strategy',
		'social media marketing',
		'email marketing campaign',
		'lead generation',
		'ppc campaign',
		'google ads management',
		'facebook ads',
		'instagram marketing',
		'influencer marketing',
		'brand awareness',
		'conversion rate optimization',
		'cro agency',

		// Crypto & Bitcoin.
		'bitcoin',
		'cryptocurrency',
		'crypto investment',
		'crypto trading',
		'blockchain',
		'ethereum',
		'usdt',
		'btc',
		'nft',
		'defi',
		'altcoin',
		'passive income crypto',
		'earn crypto',
		'crypto opportunity',
		'invest in crypto',
		'double your bitcoin',
		'crypto wallet',
		'staking rewards',
		'yield farming',
		'airdrop',
		'presale',
		'ico',
		'web3',
		'decentralized finance',
		'profit guaranteed',
		'risk-free investment',

		// Sales & Cold Outreach.
		'we noticed your website',
		'i came across your website',
		'i visited your site',
		'we can help you grow',
		'i wanted to reach out',
		'mutual benefit',
		'business proposal',
		'business opportunity',
		'collaboration opportunity',
		'partnership opportunity',
		'i have a proposal',
		'exclusive offer',
		'limited time offer',
		'act now',
		'special discount',
		'free audit',
		'free consultation',
		'no obligation',
		'results guaranteed',
		'proven results',
		'money back guarantee',
		'satisfaction guaranteed',
		'100% guaranteed',

		// Cheap Dev & Design.
		'web design services',
		'website redesign',
		'we will redesign your website',
		'mobile-friendly website',
		'e-commerce solution',
		'shopify development',
		'wordpress development',
		'cheap website',
		'affordable website',
		'professional website',
		'custom website',
		'website from scratch',
		'app development',
		'software development',
		'offshore development',
		'dedicated developer',
		'hire developer',

		// Financial Scams & Investments.
		'investment opportunity',
		'high returns',
		'guaranteed profit',
		'earn money online',
		'make money fast',
		'work from home',
		'passive income',
		'financial freedom',
		'forex trading',
		'stock tips',
		'trading signals',
		'binary options',
		'ponzi',
		'pyramid scheme',
		'get rich quick',
		'residual income',
		'multiple streams of income',
		'network marketing',
		'mlm',

		// Common Spam Patterns.
		'click here',
		'click the link',
		'visit our website',
		'check out our website',
		'.xyz',
		'.top',
		'.club',
		'you have been selected',
		'congratulations',
		'you won',
		'claim your prize',
		'verify your account',
		'urgent action required',
		'your account has been compromised',

		// General.
		'casino',
		'viagra',
		'cbd',
		'diet pills',
		'weight loss',
	);

	/**
	 * @param IpResolver      $ip_resolver IP detection dependency.
	 * @param FormLogger      $logger      Form submission logger.
	 * @param CaptchaProvider $captcha     CAPTCHA verification provider.
	 */
	public function __construct( IpResolver $ip_resolver, FormLogger $logger, CaptchaProvider $captcha ) {
		$this->ip_resolver = $ip_resolver;
		$this->logger      = $logger;
		$this->captcha     = $captcha;
	}

	/**
	 * Register all hooks for spam filtering.
	 */
	public function register(): void {
		// Honeypot field injection via JavaScript in footer.
		add_action( 'wp_footer', array( $this, 'inject_honeypot_js' ) );

		// Elementor Pro.
		add_action( 'elementor_pro/forms/validation', array( $this, 'validate_elementor' ), 10, 2 );
		add_action( 'elementor_pro/forms/new_record', array( $this, 'log_elementor_success' ), 10, 2 );

		// Contact Form 7.
		add_filter( 'wpcf7_spam', array( $this, 'validate_cf7' ), 10, 2 );
		add_action( 'wpcf7_mail_sent', array( $this, 'log_cf7_success' ) );

		// Gravity Forms.
		add_filter( 'gform_validation', array( $this, 'validate_gravity' ) );
		add_action( 'gform_after_submission', array( $this, 'log_gravity_success' ), 10, 2 );

		// Formidable Forms.
		add_filter( 'frm_validate_entry', array( $this, 'validate_formidable' ), 10, 2 );
		add_action( 'frm_after_create_entry', array( $this, 'log_formidable_success' ), 10, 2 );
	}

	/**
	 * Get plugin settings with defaults.
	 *
	 * @return array Settings array with honeypot_enabled and blocked_keywords.
	 */
	private function get_settings(): array {
		$defaults = array(
			'honeypot_enabled' => true,
			'blocked_keywords' => $this->default_keywords,
		);

		$settings = get_option( 'bc_security_settings', array() );

		return wp_parse_args( $settings, $defaults );
	}

	/**
	 * Check if the honeypot field was filled (bot detected).
	 *
	 * @return bool True if honeypot was triggered.
	 */
	private function is_honeypot_triggered(): bool {
		$settings = $this->get_settings();

		if ( ! $settings['honeypot_enabled'] ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified by the form plugin.
		return ! empty( $_POST['bc_hp_field'] );
	}

	/**
	 * Check form field values against the blocked keywords list.
	 *
	 * @param array $fields Associative array of field name => value pairs.
	 * @return string|null The matched keyword, or null if no match.
	 */
	private function check_keywords( array $fields ): ?string {
		$settings = $this->get_settings();
		$keywords = $settings['blocked_keywords'];

		if ( empty( $keywords ) ) {
			return null;
		}

		foreach ( $fields as $value ) {
			if ( ! is_string( $value ) ) {
				continue;
			}

			$value_lower = strtolower( $value );

			foreach ( $keywords as $keyword ) {
				$keyword = trim( $keyword );
				if ( empty( $keyword ) ) {
					continue;
				}

				if ( strpos( $value_lower, strtolower( $keyword ) ) !== false ) {
					return $keyword;
				}
			}
		}

		return null;
	}

	/**
	 * Verify CAPTCHA token and log if blocked.
	 *
	 * @param string $form_plugin Form plugin identifier.
	 * @param array  $fields      Form field data for logging.
	 * @return string|null Block reason if CAPTCHA failed, null if passed.
	 */
	private function check_captcha( string $form_plugin, array $fields ): ?string {
		$result = $this->captcha->verify();

		if ( ! $result['success'] ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => $result['reason'] ?? 'captcha_failed',
				'form_plugin'  => $form_plugin,
				'page_url'     => $this->get_page_url(),
				'form_data'    => $fields,
			) );
			return $result['reason'] ?? 'captcha_failed';
		}

		return null;
	}

	/**
	 * Get the current page URL from the referer or server request URI.
	 *
	 * @return string Page URL.
	 */
	private function get_page_url(): string {
		if ( ! empty( $_SERVER['HTTP_REFERER'] ) ) {
			return esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) );
		}

		if ( ! empty( $_SERVER['REQUEST_URI'] ) ) {
			return esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) );
		}

		return '';
	}

	/**
	 * Extract text fields from POST data, excluding known non-text fields.
	 *
	 * @return array Associative array of field name => value.
	 */
	private function get_post_text_fields(): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified by the form plugin.
		$post_data = $_POST;
		$fields    = array();

		$skip_keys = array(
			'bc_hp_field',
			'_wpnonce',
			'_wp_http_referer',
			'action',
			'form_id',
			'post_id',
			'queried_id',
			'referrer_title',
		);

		foreach ( $post_data as $key => $value ) {
			if ( in_array( $key, $skip_keys, true ) ) {
				continue;
			}

			if ( is_string( $value ) ) {
				$fields[ $key ] = sanitize_text_field( $value );
			}
		}

		return $fields;
	}

	/* =====================================================================
	 * Honeypot JavaScript injection
	 * ===================================================================== */

	/**
	 * Inject the honeypot hidden field into all forms via JavaScript.
	 *
	 * Uses JS injection (not server-side HTML) to avoid caching issues.
	 */
	public function inject_honeypot_js(): void {
		$settings = $this->get_settings();

		if ( ! $settings['honeypot_enabled'] ) {
			return;
		}

		?>
		<script>
		(function() {
			document.addEventListener('DOMContentLoaded', function() {
				var forms = document.querySelectorAll('form');
				for (var i = 0; i < forms.length; i++) {
					var input = document.createElement('input');
					input.type = 'text';
					input.name = 'bc_hp_field';
					input.style.cssText = 'display:none !important';
					input.tabIndex = -1;
					input.autocomplete = 'off';
					input.value = '';
					forms[i].appendChild(input);
				}
			});
		})();
		</script>
		<?php
	}

	/* =====================================================================
	 * Elementor Pro
	 * ===================================================================== */

	/**
	 * Validate Elementor Pro form submission.
	 *
	 * @param \ElementorPro\Modules\Forms\Classes\Form_Record  $record Form record.
	 * @param \ElementorPro\Modules\Forms\Classes\Ajax_Handler $handler AJAX handler.
	 */
	public function validate_elementor( $record, $handler ): void {
		$fields   = array();
		$raw      = $record->get( 'fields' );

		foreach ( $raw as $field ) {
			if ( ! empty( $field['value'] ) && is_string( $field['value'] ) ) {
				$fields[ $field['id'] ] = $field['value'];
			}
		}

		// CAPTCHA check.
		$captcha_reason = $this->check_captcha( 'elementor', $fields );
		if ( $captcha_reason !== null ) {
			$handler->add_error_message( 'Your submission could not be processed.' );
			$handler->add_error( 'bc_spam', 'Your submission could not be processed.' );
			return;
		}

		// Honeypot check.
		if ( $this->is_honeypot_triggered() ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'honeypot',
				'form_plugin'  => 'elementor',
				'page_url'     => $this->get_page_url(),
				'form_data'    => $fields,
			) );
			$handler->add_error_message( 'Your submission could not be processed.' );
			$handler->add_error( 'bc_spam', 'Your submission could not be processed.' );
			return;
		}

		// Keyword check.
		$matched_keyword = $this->check_keywords( $fields );
		if ( $matched_keyword !== null ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'keyword:' . $matched_keyword,
				'form_plugin'  => 'elementor',
				'page_url'     => $this->get_page_url(),
				'form_data'    => $fields,
			) );
			$handler->add_error_message( 'Your submission could not be processed.' );
			$handler->add_error( 'bc_spam', 'Your submission could not be processed.' );
			return;
		}
	}

	/**
	 * Log successful Elementor Pro form submission.
	 *
	 * @param \ElementorPro\Modules\Forms\Classes\Form_Record  $record  Form record.
	 * @param \ElementorPro\Modules\Forms\Classes\Ajax_Handler $handler AJAX handler.
	 */
	public function log_elementor_success( $record, $handler ): void {
		$fields = array();
		$raw    = $record->get( 'fields' );

		foreach ( $raw as $field ) {
			if ( ! empty( $field['value'] ) && is_string( $field['value'] ) ) {
				$fields[ $field['id'] ] = $field['value'];
			}
		}

		$this->logger->log( array(
			'ip'           => $this->ip_resolver->get_client_ip(),
			'status'       => 'sent',
			'block_reason' => null,
			'form_plugin'  => 'elementor',
			'page_url'     => $this->get_page_url(),
			'form_data'    => $fields,
		) );
	}

	/* =====================================================================
	 * Contact Form 7
	 * ===================================================================== */

	/**
	 * Validate Contact Form 7 submission via the wpcf7_spam filter.
	 *
	 * @param bool                    $spam    Whether the submission is spam.
	 * @param \WPCF7_Submission|null  $submission CF7 submission object.
	 * @return bool True if spam, false if not.
	 */
	public function validate_cf7( $spam, $submission = null ): bool {
		if ( $spam ) {
			return $spam;
		}

		$fields = $this->get_post_text_fields();

		// CAPTCHA check.
		$captcha_reason = $this->check_captcha( 'cf7', $fields );
		if ( $captcha_reason !== null ) {
			return true;
		}

		// Honeypot check.
		if ( $this->is_honeypot_triggered() ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'honeypot',
				'form_plugin'  => 'cf7',
				'page_url'     => $this->get_page_url(),
				'form_data'    => $fields,
			) );
			return true;
		}

		// Keyword check.
		$matched_keyword = $this->check_keywords( $fields );
		if ( $matched_keyword !== null ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'keyword:' . $matched_keyword,
				'form_plugin'  => 'cf7',
				'page_url'     => $this->get_page_url(),
				'form_data'    => $fields,
			) );
			return true;
		}

		return false;
	}

	/**
	 * Log successful Contact Form 7 submission.
	 *
	 * @param \WPCF7_ContactForm $contact_form CF7 form object.
	 */
	public function log_cf7_success( $contact_form ): void {
		$this->logger->log( array(
			'ip'           => $this->ip_resolver->get_client_ip(),
			'status'       => 'sent',
			'block_reason' => null,
			'form_plugin'  => 'cf7',
			'page_url'     => $this->get_page_url(),
			'form_data'    => $this->get_post_text_fields(),
		) );
	}

	/* =====================================================================
	 * Gravity Forms
	 * ===================================================================== */

	/**
	 * Validate Gravity Forms submission.
	 *
	 * @param array $validation_result Gravity Forms validation result array.
	 * @return array Modified validation result.
	 */
	public function validate_gravity( $validation_result ): array {
		if ( ! $validation_result['is_valid'] ) {
			return $validation_result;
		}

		$fields = $this->get_post_text_fields();

		// CAPTCHA check.
		$captcha_reason = $this->check_captcha( 'gravity', $fields );
		if ( $captcha_reason !== null ) {
			$validation_result['is_valid'] = false;
			foreach ( $validation_result['form']['fields'] as &$field ) {
				$field->failed_validation  = true;
				$field->validation_message = 'Your submission could not be processed.';
				break;
			}
			return $validation_result;
		}

		// Honeypot check.
		if ( $this->is_honeypot_triggered() ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'honeypot',
				'form_plugin'  => 'gravity',
				'page_url'     => $this->get_page_url(),
				'form_data'    => $fields,
			) );
			$validation_result['is_valid'] = false;
			foreach ( $validation_result['form']['fields'] as &$field ) {
				$field->failed_validation  = true;
				$field->validation_message = 'Your submission could not be processed.';
				break;
			}
			return $validation_result;
		}

		// Keyword check.
		$matched_keyword = $this->check_keywords( $fields );
		if ( $matched_keyword !== null ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'keyword:' . $matched_keyword,
				'form_plugin'  => 'gravity',
				'page_url'     => $this->get_page_url(),
				'form_data'    => $fields,
			) );
			$validation_result['is_valid'] = false;
			foreach ( $validation_result['form']['fields'] as &$field ) {
				$field->failed_validation  = true;
				$field->validation_message = 'Your submission could not be processed.';
				break;
			}
			return $validation_result;
		}

		return $validation_result;
	}

	/**
	 * Log successful Gravity Forms submission.
	 *
	 * @param array $entry Gravity Forms entry data.
	 * @param array $form  Gravity Forms form data.
	 */
	public function log_gravity_success( $entry, $form ): void {
		$fields = array();
		foreach ( $form['fields'] as $field ) {
			$field_id = (string) $field->id;
			if ( isset( $entry[ $field_id ] ) && is_string( $entry[ $field_id ] ) ) {
				$fields[ $field->label ] = $entry[ $field_id ];
			}
		}

		$this->logger->log( array(
			'ip'           => $this->ip_resolver->get_client_ip(),
			'status'       => 'sent',
			'block_reason' => null,
			'form_plugin'  => 'gravity',
			'page_url'     => $this->get_page_url(),
			'form_data'    => $fields,
		) );
	}

	/* =====================================================================
	 * Formidable Forms
	 * ===================================================================== */

	/**
	 * Validate Formidable Forms submission.
	 *
	 * @param array $errors Existing validation errors.
	 * @param array $values Submitted form values.
	 * @return array Errors array, with additions if spam detected.
	 */
	public function validate_formidable( $errors, $values ): array {
		$fields = $this->get_post_text_fields();

		// CAPTCHA check.
		$captcha_reason = $this->check_captcha( 'formidable', $fields );
		if ( $captcha_reason !== null ) {
			$errors['bc_spam'] = 'Your submission could not be processed.';
			return $errors;
		}

		// Honeypot check.
		if ( $this->is_honeypot_triggered() ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'honeypot',
				'form_plugin'  => 'formidable',
				'page_url'     => $this->get_page_url(),
				'form_data'    => $fields,
			) );
			$errors['bc_spam'] = 'Your submission could not be processed.';
			return $errors;
		}

		// Keyword check.
		$matched_keyword = $this->check_keywords( $fields );
		if ( $matched_keyword !== null ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'keyword:' . $matched_keyword,
				'form_plugin'  => 'formidable',
				'page_url'     => $this->get_page_url(),
				'form_data'    => $fields,
			) );
			$errors['bc_spam'] = 'Your submission could not be processed.';
			return $errors;
		}

		return $errors;
	}

	/**
	 * Log successful Formidable Forms submission.
	 *
	 * @param int   $entry_id Created entry ID.
	 * @param array $form_id  Form ID.
	 */
	public function log_formidable_success( $entry_id, $form_id ): void {
		$this->logger->log( array(
			'ip'           => $this->ip_resolver->get_client_ip(),
			'status'       => 'sent',
			'block_reason' => null,
			'form_plugin'  => 'formidable',
			'page_url'     => $this->get_page_url(),
			'form_data'    => $this->get_post_text_fields(),
		) );
	}
}
