<?php
/**
 * Admin page — settings and form submission logs.
 *
 * Provides a "BC Security" menu page with two tabs:
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
	 * @param FormLogger $logger Form submission logger.
	 */
	public function __construct( FormLogger $logger ) {
		$this->logger = $logger;
	}

	/**
	 * Register WordPress hooks for the admin page.
	 */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_menu_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_init', array( $this, 'handle_clear_logs' ) );
	}

	/**
	 * Add the "BC Security" top-level admin menu page.
	 */
	public function add_menu_page(): void {
		add_menu_page(
			'BC Security',
			'BC Security',
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
	}

	/**
	 * Sanitize settings before saving.
	 *
	 * @param array $input Raw input from the settings form.
	 * @return array Sanitized settings.
	 */
	public function sanitize_settings( $input ): array {
		$sanitized = array();

		$sanitized['honeypot_enabled'] = ! empty( $input['honeypot_enabled'] );

		$keywords_raw = isset( $input['blocked_keywords'] ) ? $input['blocked_keywords'] : '';
		$keywords     = array_map( 'trim', explode( "\n", $keywords_raw ) );
		$keywords     = array_filter( $keywords, function ( $keyword ) {
			return $keyword !== '';
		} );
		$keywords     = array_map( 'sanitize_text_field', $keywords );
		$keywords     = array_values( $keywords );

		$sanitized['blocked_keywords'] = $keywords;

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
			<h1>BC Security</h1>

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
