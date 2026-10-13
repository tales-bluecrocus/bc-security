<?php
/**
 * Spam filter — honeypot, language and keyword-based spam blocking for contact forms.
 *
 * Hooks into Elementor Pro, Contact Form 7, Gravity Forms, and Formidable Forms
 * to inject a honeypot field and check submissions against the blocked alphabets
 * and the blocked keywords list.
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
	 * @var ElementorCaptcha
	 */
	private $elementor;

	/**
	 * Alphabets a submission can be blocked for, keyed by the slug stored in
	 * blocked_scripts. The only copy: the settings page builds its tick boxes from it.
	 */
	public const SCRIPTS = array(
		'cyrillic' => array(
			'label'   => 'Russian / Ukrainian (Cyrillic)',
			'pattern' => '/\p{Cyrillic}/u',
		),
		'han'      => array(
			'label'   => 'Chinese characters (also used in Japanese)',
			'pattern' => '/\p{Han}/u',
		),
		'arabic'   => array(
			'label'   => 'Arabic (also Persian and Urdu)',
			'pattern' => '/\p{Arabic}/u',
		),
	);

	/**
	 * Default blocked keywords used when settings have not been saved yet. The only
	 * copy: the settings page shows this same list, so saving it changes nothing.
	 *
	 * A keyword added here must also go in KeywordMigration::ADDED, or it never
	 * reaches a site that already has a saved list.
	 */
	public const DEFAULT_KEYWORDS = array(
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
		'rank higher on google',
		'could rank higher',
		'directoryinspector.com',

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
		'trezor suite',
		'trezor-suite-us.com',

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
		'cold outreach',
		'email outreach',
		'outreach campaign',
		'b2b data',
		'freeb2bdata',
		'companyscout',
		'ultraleadgeneration.com',
		'blastleadgeneration',

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
		'redesign your website',
		'ai agent',
		'dandyaisoftware.com',
		'virtual assistant',
		'toptalentvas.com',
		'proxy service',
		'zero downtime',

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
	 * @param IpResolver            $ip_resolver IP detection dependency.
	 * @param FormLogger            $logger      Form submission logger.
	 * @param CaptchaProvider       $captcha     CAPTCHA verification provider.
	 * @param ElementorCaptcha|null $elementor   Elementor reCAPTCHA detection.
	 */
	public function __construct( IpResolver $ip_resolver, FormLogger $logger, CaptchaProvider $captcha, ?ElementorCaptcha $elementor = null ) {
		$this->ip_resolver = $ip_resolver;
		$this->logger      = $logger;
		$this->captcha     = $captcha;
		$this->elementor   = $elementor ? $elementor : new ElementorCaptcha();
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
	 * @return array Settings array with honeypot_enabled, blocked_keywords and blocked_scripts.
	 */
	private function get_settings(): array {
		$defaults = array(
			'honeypot_enabled' => true,
			'blocked_keywords' => self::DEFAULT_KEYWORDS,
			'blocked_scripts'  => array_keys( self::SCRIPTS ),
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
	 * Keywords match as whole words: found anywhere in the text, "ico" blocked
	 * everyone called Nicole and "defi" every message saying "definitely".
	 *
	 * @param array $fields Associative array of field name => value pairs.
	 * @return string|null The matched keyword, or null if no match.
	 */
	private function check_keywords( array $fields ): ?string {
		$settings = $this->get_settings();
		$keywords = $settings['blocked_keywords'];

		if ( empty( $keywords ) || ! is_array( $keywords ) ) {
			return null;
		}

		$patterns = array();

		foreach ( $keywords as $keyword ) {
			$keyword = is_string( $keyword ) ? trim( $keyword ) : '';
			if ( '' !== $keyword ) {
				$patterns[ $keyword ] = $this->keyword_pattern( $keyword );
			}
		}

		foreach ( $fields as $value ) {
			if ( ! is_string( $value ) ) {
				continue;
			}

			foreach ( $patterns as $keyword => $pattern ) {
				$found = preg_match( $pattern, $value );

				// Text PCRE cannot read (broken UTF-8) falls back to the plain
				// search, so the filter never switches itself off.
				if ( false === $found ) {
					$found = false !== stripos( $value, (string) $keyword );
				}

				if ( $found ) {
					return (string) $keyword;
				}
			}
		}

		return null;
	}

	/**
	 * Build the whole-word pattern for one keyword.
	 *
	 * A word edge is required only on a side where the keyword itself starts or ends
	 * with a letter or digit, so ".xyz" and "#1 on google" keep working. A plural
	 * ending is allowed ("ai agent" catches "AI agents"), an apostrophe plus a letter
	 * continues the word ("you won" must not catch "you won't"), and a space in the
	 * keyword matches any run of whitespace.
	 *
	 * @param string $keyword Trimmed, non-empty keyword.
	 * @return string PCRE pattern.
	 */
	private function keyword_pattern( string $keyword ): string {
		$words = preg_split( '/\s+/', $keyword, -1, PREG_SPLIT_NO_EMPTY );
		$body  = implode( '\s+', array_map( function ( $word ) {
			return preg_quote( $word, '/' );
		}, $words ) );

		$left  = preg_match( '/^[\p{L}\p{N}]/u', $keyword ) ? '(?<![\p{L}\p{N}])' : '';
		$right = preg_match( '/[\p{L}\p{N}]$/u', $keyword ) ? '(?:e?s)?(?![\p{L}\p{N}]|[\'’]\p{L})' : '';

		return '/' . $left . $body . $right . '/iu';
	}

	/**
	 * Check form field values for a blocked alphabet.
	 *
	 * Any single letter counts: foreign-language spam is caught whole, and so is the
	 * trick of swapping in look-alike Cyrillic letters to slip past the keyword list.
	 * Text PCRE cannot read is let through rather than blocking everyone.
	 *
	 * @param array $fields Associative array of field name => value pairs.
	 * @return string|null Slug of the matched alphabet, or null if no match.
	 */
	private function check_scripts( array $fields ): ?string {
		$settings = $this->get_settings();
		$scripts  = is_array( $settings['blocked_scripts'] ) ? $settings['blocked_scripts'] : array();

		foreach ( $fields as $value ) {
			if ( ! is_string( $value ) ) {
				continue;
			}

			foreach ( $scripts as $slug ) {
				if ( is_string( $slug ) && isset( self::SCRIPTS[ $slug ] ) && 1 === preg_match( self::SCRIPTS[ $slug ]['pattern'], $value ) ) {
					return $slug;
				}
			}
		}

		return null;
	}

	/**
	 * Verify CAPTCHA token and log if blocked.
	 *
	 * Uses whichever contact-form mode is in force on this site: the main checkbox
	 * or invisible reCAPTCHA v3. Off (the default, and whenever the needed keys have
	 * not passed Test Keys) means no CAPTCHA check at all.
	 *
	 * @param string $form_plugin Form plugin identifier.
	 * @param array  $fields      Form field data for logging.
	 * @param bool   $skip        True when this submission is not ours to check.
	 * @return string|null Block reason if CAPTCHA failed, null if passed.
	 */
	private function check_captcha( string $form_plugin, array $fields, bool $skip = false ): ?string {
		$mode = $this->captcha->forms_mode();

		if ( 'off' === $mode || $skip ) {
			return null;
		}

		$result = $this->captcha->verify_pair( 'checkbox' === $mode ? 'main' : 'v3' );

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

		// CAPTCHA tokens are 1–2 KB of random base64. Scanned as text, short keywords
		// ("seo", "btc", "nft", "ico", "cbd", "mlm") turn up in roughly a quarter of
		// them by pure chance, silently blocking real visitors as spam.
		$skip_keys = array(
			'bc_hp_field',
			'_wpnonce',
			'_wp_http_referer',
			'action',
			'form_id',
			'post_id',
			'queried_id',
			'referrer_title',
			'bc_captcha_token',
			'bc_captcha_error',
			'g-recaptcha-response',
			'cf-turnstile-response',
			'_wpcf7_recaptcha_response',
		);

		foreach ( $post_data as $key => $value ) {
			if ( in_array( $key, $skip_keys, true ) ) {
				continue;
			}

			$this->collect_text( (string) $key, wp_unslash( $value ), $fields );
		}

		return $fields;
	}

	/**
	 * Add a POST value to the field list, walking into nested values.
	 *
	 * Formidable posts every answer as item_meta[ID], and checkbox groups arrive as
	 * arrays in every plugin; read top-level only, those were never checked.
	 *
	 * @param string $key    Field name; nested keys are joined with a dot.
	 * @param mixed  $value  Unslashed POST value.
	 * @param array  $fields Collected fields, by reference.
	 * @param int    $depth  Current nesting depth.
	 */
	private function collect_text( string $key, $value, array &$fields, int $depth = 0 ): void {
		if ( is_string( $value ) ) {
			$fields[ $key ] = sanitize_text_field( $value );
			return;
		}

		if ( is_array( $value ) && $depth < 5 ) {
			foreach ( $value as $sub_key => $sub_value ) {
				$this->collect_text( $key . '.' . $sub_key, $sub_value, $fields, $depth + 1 );
			}
		}
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

		// CAPTCHA check. Forms carrying Elementor's own configured reCAPTCHA are
		// left to Elementor, which verifies that field itself.
		$captcha_reason = $this->check_captcha( 'elementor', $fields, $this->elementor->form_has_own_captcha( $record ) );
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

		// Language check.
		$matched_script = $this->check_scripts( $fields );
		if ( $matched_script !== null ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'language:' . $matched_script,
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

		// Language check.
		$matched_script = $this->check_scripts( $fields );
		if ( $matched_script !== null ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'language:' . $matched_script,
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

		// CAPTCHA check, on the final submission only. Gravity runs this filter for
		// every "Next" on a multi-page form too, where no check is shown; its hidden
		// target-page field is 0 only when the form is actually being submitted.
		$form_id     = isset( $validation_result['form']['id'] ) ? absint( $validation_result['form']['id'] ) : 0;
		$target_key  = 'gform_target_page_number_' . $form_id;
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Routing only; Gravity verifies its own submission.
		$target_page = isset( $_POST[ $target_key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $target_key ] ) ) : '0';
		$not_final   = '' !== $target_page && '0' !== $target_page;

		$captcha_reason = $this->check_captcha( 'gravity', $fields, $not_final );
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

		// Language check.
		$matched_script = $this->check_scripts( $fields );
		if ( $matched_script !== null ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'language:' . $matched_script,
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

		// Language check.
		$matched_script = $this->check_scripts( $fields );
		if ( $matched_script !== null ) {
			$this->logger->log( array(
				'ip'           => $this->ip_resolver->get_client_ip(),
				'status'       => 'blocked',
				'block_reason' => 'language:' . $matched_script,
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
