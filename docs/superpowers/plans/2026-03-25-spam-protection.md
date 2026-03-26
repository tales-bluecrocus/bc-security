# Spam Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add honeypot and keyword-based spam filtering for contact forms with admin settings page and submission logs.

**Architecture:** SpamFilter hooks into Elementor Pro/CF7/Gravity/Formidable form validation to check honeypot field and keyword matches. FormLogger persists results to a custom DB table. AdminPage provides settings (honeypot toggle, keyword list) and a WP_List_Table-based log viewer with filtering and pagination.

**Tech Stack:** PHP 7.4+, WordPress 5.0+, WordPress Settings API, WP_List_Table, wpdb

**Spec:** `docs/superpowers/specs/2026-03-25-spam-protection-design.md`

---

## Task 1: Database class + table migration

Create `src/Database.php` with a `maybe_create_tables()` method that creates the `{prefix}bc_form_logs` table using `dbDelta()`. The version is stored in the `bc_security_db_version` option so migrations only run when needed.

### Steps

- [ ] **1.1** Create `src/Database.php` with the following content:

```php
<?php
/**
 * Database table creation and migration.
 *
 * Creates and updates the bc_form_logs table used by the spam protection feature.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class Database {

	/**
	 * Current database schema version.
	 */
	const DB_VERSION = '1.0.0';

	/**
	 * Option name for tracking the installed DB version.
	 */
	const VERSION_OPTION = 'bc_security_db_version';

	/**
	 * Create or update tables if the schema version has changed.
	 *
	 * Called on plugins_loaded and register_activation_hook.
	 */
	public function maybe_create_tables(): void {
		$installed_version = get_option( self::VERSION_OPTION, '' );

		if ( $installed_version === self::DB_VERSION ) {
			return;
		}

		$this->create_form_logs_table();
		update_option( self::VERSION_OPTION, self::DB_VERSION );
	}

	/**
	 * Create the bc_form_logs table using dbDelta.
	 */
	private function create_form_logs_table(): void {
		global $wpdb;

		$table_name      = $wpdb->prefix . 'bc_form_logs';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL,
			ip VARCHAR(45) NOT NULL,
			status VARCHAR(10) NOT NULL,
			block_reason VARCHAR(100) DEFAULT NULL,
			form_plugin VARCHAR(50) NOT NULL,
			page_url VARCHAR(255) NOT NULL,
			form_data TEXT NOT NULL,
			PRIMARY KEY  (id),
			KEY idx_created_at (created_at),
			KEY idx_status (status)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}
}
```

- [ ] **1.2** Verify syntax:

```bash
php -l src/Database.php
```

- [ ] **1.3** Commit:

```bash
git add src/Database.php
git commit -m "Add Database class for bc_form_logs table migration"
```

---

## Task 2: FormLogger class

Create `src/FormLogger.php` with methods to insert, query, count, and clear log entries. All database access uses `$wpdb->prepare()`.

### Steps

- [ ] **2.1** Create `src/FormLogger.php` with the following content:

```php
<?php
/**
 * Form submission logger.
 *
 * Inserts and queries log entries in the bc_form_logs table.
 * Used by SpamFilter to record submissions and by AdminPage to display them.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class FormLogger {

	/**
	 * Get the full table name with prefix.
	 *
	 * @return string Table name.
	 */
	private function table_name(): string {
		global $wpdb;

		return $wpdb->prefix . 'bc_form_logs';
	}

	/**
	 * Log a form submission.
	 *
	 * @param array $data {
	 *     Submission data.
	 *
	 *     @type string $ip           Client IP address.
	 *     @type string $status       'sent' or 'blocked'.
	 *     @type string $block_reason Reason for blocking, or null if sent.
	 *     @type string $form_plugin  Plugin identifier (elementor, cf7, gravity, formidable).
	 *     @type string $page_url     URL where the form was submitted.
	 *     @type array  $form_data    Form fields (name, email, message, etc.).
	 * }
	 */
	public function log( array $data ): void {
		global $wpdb;

		$wpdb->insert(
			$this->table_name(),
			array(
				'created_at'   => current_time( 'mysql', true ),
				'ip'           => sanitize_text_field( $data['ip'] ),
				'status'       => sanitize_text_field( $data['status'] ),
				'block_reason' => isset( $data['block_reason'] ) ? sanitize_text_field( $data['block_reason'] ) : null,
				'form_plugin'  => sanitize_text_field( $data['form_plugin'] ),
				'page_url'     => esc_url_raw( $data['page_url'] ),
				'form_data'    => wp_json_encode( $data['form_data'] ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Retrieve log entries with filtering, pagination, and sorting.
	 *
	 * @param array $args {
	 *     Query arguments.
	 *
	 *     @type string $status   Filter by status ('sent', 'blocked', or empty for all).
	 *     @type string $search   Search term matched against IP and block_reason.
	 *     @type int    $per_page Number of results per page. Default 25.
	 *     @type int    $page     Page number (1-based). Default 1.
	 *     @type string $orderby  Column to sort by. Default 'created_at'.
	 *     @type string $order    Sort direction ('ASC' or 'DESC'). Default 'DESC'.
	 * }
	 * @return array Array of row objects.
	 */
	public function get_logs( array $args = array() ): array {
		global $wpdb;

		$defaults = array(
			'status'   => '',
			'search'   => '',
			'per_page' => 25,
			'page'     => 1,
			'orderby'  => 'created_at',
			'order'    => 'DESC',
		);

		$args  = wp_parse_args( $args, $defaults );
		$table = $this->table_name();

		$where_clauses = array();
		$where_values  = array();

		if ( ! empty( $args['status'] ) ) {
			$where_clauses[] = 'status = %s';
			$where_values[]  = $args['status'];
		}

		if ( ! empty( $args['search'] ) ) {
			$where_clauses[] = '(ip LIKE %s OR block_reason LIKE %s)';
			$search_term     = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where_values[]  = $search_term;
			$where_values[]  = $search_term;
		}

		$where = '';
		if ( ! empty( $where_clauses ) ) {
			$where = 'WHERE ' . implode( ' AND ', $where_clauses );
		}

		$allowed_orderby = array( 'created_at', 'id', 'status', 'ip' );
		$orderby         = in_array( $args['orderby'], $allowed_orderby, true ) ? $args['orderby'] : 'created_at';
		$order           = strtoupper( $args['order'] ) === 'ASC' ? 'ASC' : 'DESC';

		$per_page = absint( $args['per_page'] );
		$offset   = ( absint( $args['page'] ) - 1 ) * $per_page;

		$sql = "SELECT * FROM {$table} {$where} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d";

		$query_values   = array_merge( $where_values, array( $per_page, $offset ) );
		$prepared_query = $wpdb->prepare( $sql, $query_values );

		return $wpdb->get_results( $prepared_query );
	}

	/**
	 * Get the total number of log entries matching the given filters.
	 *
	 * @param array $args {
	 *     Filter arguments (same as get_logs but pagination keys are ignored).
	 *
	 *     @type string $status Filter by status.
	 *     @type string $search Search term matched against IP and block_reason.
	 * }
	 * @return int Total row count.
	 */
	public function get_total( array $args = array() ): int {
		global $wpdb;

		$table = $this->table_name();

		$where_clauses = array();
		$where_values  = array();

		if ( ! empty( $args['status'] ) ) {
			$where_clauses[] = 'status = %s';
			$where_values[]  = $args['status'];
		}

		if ( ! empty( $args['search'] ) ) {
			$where_clauses[] = '(ip LIKE %s OR block_reason LIKE %s)';
			$search_term     = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where_values[]  = $search_term;
			$where_values[]  = $search_term;
		}

		$where = '';
		if ( ! empty( $where_clauses ) ) {
			$where = 'WHERE ' . implode( ' AND ', $where_clauses );
		}

		if ( ! empty( $where_values ) ) {
			return (int) $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} {$where}",
				$where_values
			) );
		}

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
	}

	/**
	 * Delete all log entries.
	 */
	public function clear_logs(): void {
		global $wpdb;

		$wpdb->query( "TRUNCATE TABLE {$this->table_name()}" );
	}
}
```

- [ ] **2.2** Verify syntax:

```bash
php -l src/FormLogger.php
```

- [ ] **2.3** Commit:

```bash
git add src/FormLogger.php
git commit -m "Add FormLogger class for form submission logging"
```

---

## Task 3: SpamFilter class — honeypot

Create `src/SpamFilter.php` with honeypot injection and validation for Elementor Pro, CF7, Gravity Forms, and Formidable. The honeypot field is injected via inline JavaScript on `wp_footer` to avoid HTML caching issues.

### Steps

- [ ] **3.1** Create `src/SpamFilter.php` with the following content:

```php
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
	 * Default blocked keywords used when settings have not been saved yet.
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
	 * @param IpResolver $ip_resolver IP detection dependency.
	 * @param FormLogger $logger      Form submission logger.
	 */
	public function __construct( IpResolver $ip_resolver, FormLogger $logger ) {
		$this->ip_resolver = $ip_resolver;
		$this->logger      = $logger;
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
```

- [ ] **3.2** Verify syntax:

```bash
php -l src/SpamFilter.php
```

- [ ] **3.3** Commit:

```bash
git add src/SpamFilter.php
git commit -m "Add SpamFilter class with honeypot protection for all form plugins"
```

---

## Task 4: SpamFilter — keyword filter

The keyword filtering logic is already included in the SpamFilter class created in Task 3. The `check_keywords()` private method and its integration into every validation hook were written together with the honeypot logic because they share the same validation flow.

This task is a verification step to confirm the implementation is correct.

### Steps

- [ ] **4.1** Verify that `src/SpamFilter.php` contains the `check_keywords()` method and that each validation hook (`validate_elementor`, `validate_cf7`, `validate_gravity`, `validate_formidable`) calls it after the honeypot check. Confirm the following are true:

1. `check_keywords()` accepts an array of field values and returns `null` (no match) or the matched keyword string.
2. Matching is case-insensitive (`strtolower` on both value and keyword).
3. Block reason is formatted as `keyword:MATCHED_WORD`.
4. Default keywords are defined in the `$default_keywords` property.
5. Keywords are loaded from `bc_security_settings` option via `get_settings()`.

No file changes needed. No commit for this task.

---

## Task 5: AdminPage class — Settings tab

Create `src/AdminPage.php` with a menu page under "BC Security" and a Settings tab using the WordPress Settings API.

### Steps

- [ ] **5.1** Create `src/AdminPage.php` with the following content:

```php
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
	 * Render the Logs tab content.
	 *
	 * This is a placeholder — the full implementation is added in Task 7.
	 */
	private function render_logs_tab(): void {
		echo '<p>Logs tab will be implemented in a later step.</p>';
	}
}
```

- [ ] **5.2** Verify syntax:

```bash
php -l src/AdminPage.php
```

- [ ] **5.3** Commit:

```bash
git add src/AdminPage.php
git commit -m "Add AdminPage class with settings tab for spam protection"
```

---

## Task 6: LogsTable class (WP_List_Table)

Create `src/LogsTable.php` that extends `WP_List_Table` to display form submission logs with sortable columns, pagination, status filter dropdown, and search box.

### Steps

- [ ] **6.1** Create `src/LogsTable.php` with the following content:

```php
<?php
/**
 * Logs table — WP_List_Table subclass for displaying form submission logs.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

class LogsTable extends \WP_List_Table {

	/**
	 * @var FormLogger
	 */
	private $logger;

	/**
	 * @param FormLogger $logger Form submission logger.
	 */
	public function __construct( FormLogger $logger ) {
		$this->logger = $logger;

		parent::__construct( array(
			'singular' => 'log',
			'plural'   => 'logs',
			'ajax'     => false,
		) );
	}

	/**
	 * Define table columns.
	 *
	 * @return array Column slug => Column label.
	 */
	public function get_columns(): array {
		return array(
			'created_at'   => 'Date',
			'ip'           => 'IP',
			'status'       => 'Status',
			'block_reason' => 'Reason',
			'form_plugin'  => 'Form Plugin',
			'page_url'     => 'Page URL',
		);
	}

	/**
	 * Define sortable columns.
	 *
	 * @return array Column slug => array( orderby value, default desc ).
	 */
	public function get_sortable_columns(): array {
		return array(
			'created_at' => array( 'created_at', true ),
		);
	}

	/**
	 * Prepare items for display — query data, set pagination.
	 */
	public function prepare_items(): void {
		$per_page = 25;

		$args = array(
			'per_page' => $per_page,
			'page'     => $this->get_pagenum(),
			'orderby'  => isset( $_GET['orderby'] ) ? sanitize_text_field( wp_unslash( $_GET['orderby'] ) ) : 'created_at',
			'order'    => isset( $_GET['order'] ) ? sanitize_text_field( wp_unslash( $_GET['order'] ) ) : 'DESC',
		);

		if ( ! empty( $_GET['status_filter'] ) ) {
			$args['status'] = sanitize_text_field( wp_unslash( $_GET['status_filter'] ) );
		}

		if ( ! empty( $_GET['s'] ) ) {
			$args['search'] = sanitize_text_field( wp_unslash( $_GET['s'] ) );
		}

		$this->items = $this->logger->get_logs( $args );
		$total_items = $this->logger->get_total( $args );

		$this->set_pagination_args( array(
			'total_items' => $total_items,
			'per_page'    => $per_page,
			'total_pages' => ceil( $total_items / $per_page ),
		) );

		$this->_column_headers = array(
			$this->get_columns(),
			array(),
			$this->get_sortable_columns(),
		);
	}

	/**
	 * Render the Date column.
	 *
	 * @param object $item Row data.
	 * @return string Formatted date.
	 */
	public function column_created_at( $item ): string {
		$utc_time   = $item->created_at;
		$local_time = get_date_from_gmt( $utc_time, 'Y-m-d H:i:s' );

		return esc_html( $local_time );
	}

	/**
	 * Render the IP column.
	 *
	 * @param object $item Row data.
	 * @return string IP address.
	 */
	public function column_ip( $item ): string {
		return esc_html( $item->ip );
	}

	/**
	 * Render the Status column with a colored badge.
	 *
	 * @param object $item Row data.
	 * @return string Status badge HTML.
	 */
	public function column_status( $item ): string {
		if ( $item->status === 'blocked' ) {
			return '<span style="background:#dc3232;color:#fff;padding:2px 8px;border-radius:3px;font-size:12px;">Blocked</span>';
		}

		return '<span style="background:#46b450;color:#fff;padding:2px 8px;border-radius:3px;font-size:12px;">Sent</span>';
	}

	/**
	 * Render the Reason column.
	 *
	 * @param object $item Row data.
	 * @return string Block reason or dash.
	 */
	public function column_block_reason( $item ): string {
		if ( empty( $item->block_reason ) ) {
			return '&mdash;';
		}

		return esc_html( $item->block_reason );
	}

	/**
	 * Render the Form Plugin column.
	 *
	 * @param object $item Row data.
	 * @return string Plugin name.
	 */
	public function column_form_plugin( $item ): string {
		$labels = array(
			'elementor'   => 'Elementor Pro',
			'cf7'         => 'Contact Form 7',
			'gravity'     => 'Gravity Forms',
			'formidable'  => 'Formidable',
		);

		$plugin = $item->form_plugin;

		return esc_html( isset( $labels[ $plugin ] ) ? $labels[ $plugin ] : $plugin );
	}

	/**
	 * Render the Page URL column.
	 *
	 * @param object $item Row data.
	 * @return string Linked URL.
	 */
	public function column_page_url( $item ): string {
		if ( empty( $item->page_url ) ) {
			return '&mdash;';
		}

		$url = esc_url( $item->page_url );

		// Show only the path portion for readability.
		$parsed = wp_parse_url( $item->page_url );
		$path   = isset( $parsed['path'] ) ? $parsed['path'] : '/';

		return '<a href="' . $url . '" target="_blank" rel="noopener">' . esc_html( $path ) . '</a>';
	}

	/**
	 * Render the status filter dropdown above the table.
	 *
	 * @param string $which Top or bottom position.
	 */
	protected function extra_tablenav( $which ): void {
		if ( $which !== 'top' ) {
			return;
		}

		$current_status = isset( $_GET['status_filter'] ) ? sanitize_text_field( wp_unslash( $_GET['status_filter'] ) ) : '';
		?>
		<div class="alignleft actions">
			<select name="status_filter">
				<option value="">All Statuses</option>
				<option value="sent" <?php selected( $current_status, 'sent' ); ?>>Sent</option>
				<option value="blocked" <?php selected( $current_status, 'blocked' ); ?>>Blocked</option>
			</select>
			<?php submit_button( 'Filter', '', 'filter_action', false ); ?>
		</div>
		<?php
	}

	/**
	 * Message displayed when no items are found.
	 */
	public function no_items(): void {
		echo 'No form submissions logged yet.';
	}
}
```

- [ ] **6.2** Verify syntax:

```bash
php -l src/LogsTable.php
```

- [ ] **6.3** Commit:

```bash
git add src/LogsTable.php
git commit -m "Add LogsTable class extending WP_List_Table for form logs"
```

---

## Task 7: AdminPage — Logs tab

Update `src/AdminPage.php` to replace the placeholder logs tab with the full implementation that integrates LogsTable, the Clear Logs button, and the search box.

### Steps

- [ ] **7.1** In `src/AdminPage.php`, replace the `render_logs_tab()` method with the full implementation. Find the placeholder method:

```php
	/**
	 * Render the Logs tab content.
	 *
	 * This is a placeholder — the full implementation is added in Task 7.
	 */
	private function render_logs_tab(): void {
		echo '<p>Logs tab will be implemented in a later step.</p>';
	}
```

Replace it with:

```php
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
```

- [ ] **7.2** Verify syntax:

```bash
php -l src/AdminPage.php
```

- [ ] **7.3** Commit:

```bash
git add src/AdminPage.php
git commit -m "Add logs tab with WP_List_Table, search, filtering, and clear button"
```

---

## Task 8: Update bootstrap + docs

Modify `bc-security.php` to instantiate the new classes (Database, FormLogger, SpamFilter, AdminPage) and add the activation hook. Update `CLAUDE.md` and `README.md` to document the new feature.

### Steps

- [ ] **8.1** In `bc-security.php`, replace the entire file content with:

```php
<?php
/**
 * Plugin Name: BC Security
 * Plugin URI:  https://bluecrocus.ca/
 * Description: WordPress security — blocks user enumeration, brute force attacks, and form spam with honeypot and keyword filtering.
 * Version:     2.1.0
 * Author:      Blue Crocus
 * Author URI:  https://bluecrocus.ca/
 * License:     GPL-2.0-or-later
 * Network:     true
 * Requires at least: 5.0
 * Requires PHP: 7.4
 *
 * @package BcSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/* =========================================================================
 * Configuration
 * ========================================================================= */

define( 'BC_SECURITY_VERSION', '2.1.0' );
define( 'BC_SECURITY_FILE', __FILE__ );
define( 'BC_MAX_ATTEMPTS', 5 );      // Failed attempts before lockout.
define( 'BC_LOCKOUT_SECONDS', 900 ); // Lockout duration: 15 minutes.

/* =========================================================================
 * Autoload & Bootstrap
 * ========================================================================= */

require __DIR__ . '/vendor/autoload.php';

// Database migration (lightweight version check).
( new BcSecurity\Database() )->maybe_create_tables();

// Security features.
( new BcSecurity\BruteForce( new BcSecurity\IpResolver() ) )->register();
( new BcSecurity\UserEnumeration() )->register();
( new BcSecurity\UpdateChecker() )->register();

// Spam protection.
$bc_logger = new BcSecurity\FormLogger();
( new BcSecurity\SpamFilter( new BcSecurity\IpResolver(), $bc_logger ) )->register();

// Admin UI.
if ( is_admin() ) {
	( new BcSecurity\AdminPage( $bc_logger ) )->register();
}

/* =========================================================================
 * Activation Hook
 * ========================================================================= */

register_activation_hook( __FILE__, function () {
	( new BcSecurity\Database() )->maybe_create_tables();
} );
```

- [ ] **8.2** Regenerate the autoloader so the new classes are discoverable:

```bash
composer dump-autoload
```

- [ ] **8.3** Verify syntax of all new and modified files:

```bash
php -l bc-security.php
php -l src/Database.php
php -l src/FormLogger.php
php -l src/SpamFilter.php
php -l src/AdminPage.php
php -l src/LogsTable.php
```

- [ ] **8.4** In `CLAUDE.md`, add the following section after the existing `## Files` section at the bottom of the file. Find the end of the Files section and append:

After the existing `Files` code block, add:

```markdown

## Spam Protection

### How it works

SpamFilter hooks into Elementor Pro, Contact Form 7, Gravity Forms, and Formidable Forms validation.
Two detection methods run on every form submission:

1. **Honeypot** — a hidden field injected via JavaScript. If a bot fills it in, the submission is blocked.
2. **Keyword filter** — all text fields are checked against a configurable list of blocked keywords (case-insensitive).

Both blocked and successful submissions are logged to the `{prefix}bc_form_logs` database table.

### Admin Page

- **Settings tab**: toggle honeypot on/off, edit blocked keywords list
- **Logs tab**: view form submissions with status filter, search, pagination, and clear button
- Menu location: "BC Security" in the WordPress admin sidebar

### Settings storage

`wp_options` key: `bc_security_settings`

```php
array(
    'honeypot_enabled' => true,
    'blocked_keywords' => array( 'seo', 'marketing', 'bitcoin', ... ),
)
```

### Database

Table: `{prefix}bc_form_logs` — created on plugin activation and checked on `plugins_loaded`.
Schema version tracked in `bc_security_db_version` option.

### Hooks used by SpamFilter

| Hook | Type | Purpose |
|------|------|---------|
| `wp_footer` | action | Inject honeypot JS |
| `elementor_pro/forms/validation` | action | Validate Elementor forms |
| `elementor_pro/forms/new_record` | action | Log successful Elementor submissions |
| `wpcf7_spam` | filter | Validate CF7 forms |
| `wpcf7_mail_sent` | action | Log successful CF7 submissions |
| `gform_validation` | filter | Validate Gravity Forms |
| `gform_after_submission` | action | Log successful Gravity submissions |
| `frm_validate_entry` | filter | Validate Formidable forms |
| `frm_after_create_entry` | action | Log successful Formidable submissions |
```

- [ ] **8.5** Update `README.md` to mention the spam protection feature. Add a "Spam Protection" section after any existing feature sections describing the honeypot, keyword filter, admin settings page, and form logs.

- [ ] **8.6** Commit all changes:

```bash
git add bc-security.php CLAUDE.md README.md
git commit -m "Wire up spam protection in bootstrap, update version to 2.1.0, update docs"
```

---

## Summary of files created/modified

| File | Action | Task |
|------|--------|------|
| `src/Database.php` | Created | 1 |
| `src/FormLogger.php` | Created | 2 |
| `src/SpamFilter.php` | Created | 3 |
| `src/AdminPage.php` | Created | 5, 7 |
| `src/LogsTable.php` | Created | 6 |
| `bc-security.php` | Modified | 8 |
| `CLAUDE.md` | Modified | 8 |
| `README.md` | Modified | 8 |
