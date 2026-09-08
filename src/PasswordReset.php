<?php
/**
 * Password reset abuse protection — rate-limits lost-password requests and closes
 * the account enumeration oracle on wp-login.php?action=lostpassword.
 *
 * Two independent controls:
 *   1. Per-IP throttle — an overt 429 once an IP exceeds BC_RESET_MAX_ATTEMPTS.
 *   2. Per-account cooldown — at most one reset email per account per
 *      BC_RESET_COOLDOWN_SECONDS, silently enforced so it leaks nothing.
 *
 * Throttle state is keyed separately from the BruteForce lockout so that reset
 * spam from a shared or NAT'd IP never blocks a legitimate login.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class PasswordReset {

	/**
	 * @var IpResolver
	 */
	private $ip_resolver;

	/**
	 * @var FormLogger|null
	 */
	private $logger;

	/**
	 * True once lostpassword_post has fired for this request.
	 *
	 * get_password_reset_key() also runs for new-user "set your password" mail,
	 * which fires retrieve_password_key without ever passing through the
	 * lost-password form. This flag scopes the cooldown to genuine reset requests.
	 *
	 * @var bool
	 */
	private $in_reset_request = false;

	/**
	 * @param IpResolver      $ip_resolver IP detection dependency.
	 * @param FormLogger|null $logger      Optional logger for the audit trail.
	 */
	public function __construct( IpResolver $ip_resolver, ?FormLogger $logger = null ) {
		$this->ip_resolver = $ip_resolver;
		$this->logger      = $logger;
	}

	/**
	 * Register all WordPress hooks for password reset protection.
	 */
	public function register(): void {
		// Throttle gate. Fires before the wp-login.php switch processes the POST;
		// core aliases both action names to the same handler, so hook both.
		add_action( 'login_form_lostpassword', array( $this, 'check_reset_throttle' ) );
		add_action( 'login_form_retrievepassword', array( $this, 'check_reset_throttle' ) );

		// Count the attempt and enforce the per-account cooldown.
		add_action( 'lostpassword_post', array( $this, 'on_reset_request' ), 10, 2 );

		// Anti-enumeration: same response whether or not the account exists.
		add_filter( 'lostpassword_errors', array( $this, 'genericize_errors' ), 10, 2 );

		// A reset key was generated, so mail is about to go out — start the cooldown.
		add_action( 'retrieve_password_key', array( $this, 'on_reset_email_sent' ), 10, 2 );
	}

	/**
	 * Block a throttled IP before wp-login.php processes the reset POST.
	 */
	public function check_reset_throttle(): void {
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
			return;
		}

		if ( ! $this->is_protection_enabled() ) {
			return;
		}

		$ip   = $this->ip_resolver->get_client_ip();
		$key  = $this->throttle_key( $ip );
		$data = get_transient( $key );

		if ( ! is_array( $data ) || $data['attempts'] < BC_RESET_MAX_ATTEMPTS ) {
			return;
		}

		$remaining = max( 0, $data['locked_until'] - time() );

		if ( $remaining <= 0 ) {
			return;
		}

		// Log once per throttle window. A bot can hit this endpoint thousands of
		// times while throttled, and a row per request would flood bc_form_logs,
		// which has no automatic pruning. locked_until is absolute, so refreshing
		// the transient TTL here does not extend the throttle itself.
		if ( empty( $data['logged'] ) ) {
			$data['logged'] = true;
			set_transient( $key, $data, BC_RESET_WINDOW_SECONDS );
			$this->log_event( 'blocked', 'pwreset_ip_limit' );
		}

		$this->send_throttle_response( $remaining );
	}

	/**
	 * Record the attempt and apply the per-account cooldown.
	 *
	 * @param \WP_Error      $errors    Error collector (unused; we exit instead).
	 * @param \WP_User|false $user_data Resolved user, or false if no match.
	 */
	public function on_reset_request( $errors, $user_data ): void {
		if ( ! $this->is_protection_enabled() || ! $this->is_web_request() ) {
			return;
		}

		$this->in_reset_request = true;

		$this->record_attempt( $this->ip_resolver->get_client_ip() );

		// Silent by design: a visible "too many requests" here would confirm the
		// account exists, reopening the oracle that genericize_errors() closes.
		if ( $user_data instanceof \WP_User && $this->is_account_cooling_down( $user_data->ID ) ) {
			$this->log_event( 'blocked', 'pwreset_cooldown' );
			$this->redirect_to_confirmation();
		}
	}

	/**
	 * Replace "no such account" errors with the ordinary success response.
	 *
	 * Core adds invalid_email before this filter and invalidcombo after it, so an
	 * unknown account arrives here in one of two shapes: the invalid_email code is
	 * already present, or the error bag is still empty and $user_data is false.
	 *
	 * @param \WP_Error      $errors    Errors collected so far.
	 * @param \WP_User|false $user_data Resolved user, or false if no match.
	 * @return \WP_Error Unmodified errors, or exits with a fake success.
	 */
	public function genericize_errors( $errors, $user_data ) {
		if ( ! $this->is_generic_response_enabled() || ! $this->is_web_request() ) {
			return $errors;
		}

		if ( ! is_wp_error( $errors ) ) {
			return $errors;
		}

		$codes       = $errors->get_error_codes();
		$enumeration = array( 'invalid_email', 'invalidcombo' );

		// A real, account-agnostic error (an empty username, or one added by another
		// plugin on lostpassword_post) must still reach the user.
		if ( ! empty( array_diff( $codes, $enumeration ) ) ) {
			return $errors;
		}

		$is_unknown_account = ! empty( array_intersect( $codes, $enumeration ) )
			|| ( empty( $codes ) && ! $user_data );

		if ( ! $is_unknown_account ) {
			return $errors;
		}

		$this->log_event( 'blocked', 'pwreset_unknown_account' );
		$this->redirect_to_confirmation();
	}

	/**
	 * Start the per-account cooldown once a reset key has been generated.
	 *
	 * @param string $user_login Login of the user being reset.
	 * @param string $key        Generated reset key (unused).
	 */
	public function on_reset_email_sent( $user_login, $key ): void {
		if ( ! $this->is_protection_enabled() || ! $this->in_reset_request ) {
			return;
		}

		$user = get_user_by( 'login', $user_login );

		if ( $user instanceof \WP_User ) {
			set_transient( $this->account_key( $user->ID ), time(), BC_RESET_COOLDOWN_SECONDS );
		}

		$this->log_event( 'sent', null );
	}

	/**
	 * Get plugin settings with defaults.
	 *
	 * @return array Settings array.
	 */
	private function get_settings(): array {
		$defaults = array(
			'pwreset_protection'       => true,
			'pwreset_generic_response' => true,
		);

		$settings = get_option( 'bc_security_settings', array() );

		return wp_parse_args( $settings, $defaults );
	}

	/**
	 * Check if reset rate limiting is enabled.
	 *
	 * @return bool
	 */
	private function is_protection_enabled(): bool {
		$settings = $this->get_settings();
		return ! empty( $settings['pwreset_protection'] );
	}

	/**
	 * Check if the generic (anti-enumeration) response is enabled.
	 *
	 * @return bool
	 */
	private function is_generic_response_enabled(): bool {
		$settings = $this->get_settings();
		return ! empty( $settings['pwreset_generic_response'] );
	}

	/**
	 * Check that we are serving a web request.
	 *
	 * retrieve_password() is also reachable from WP-CLI and cron, where issuing a
	 * redirect or wp_die() would be wrong.
	 *
	 * @return bool
	 */
	private function is_web_request(): bool {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return false;
		}

		return ! wp_doing_cron();
	}

	/**
	 * Get the throttle transient key for a given IP.
	 *
	 * @param string $ip Client IP address.
	 * @return string Transient key.
	 */
	private function throttle_key( string $ip ): string {
		return 'bc_pwreset_ip_' . md5( $ip );
	}

	/**
	 * Get the cooldown transient key for a given account.
	 *
	 * Keyed on the resolved user ID so that "admin", "Admin" and the account's
	 * email address all share a single cooldown.
	 *
	 * @param int $user_id User ID.
	 * @return string Transient key.
	 */
	private function account_key( int $user_id ): string {
		return 'bc_pwreset_acct_' . $user_id;
	}

	/**
	 * Record a reset request against an IP.
	 *
	 * @param string $ip Client IP address.
	 */
	private function record_attempt( string $ip ): void {
		$key  = $this->throttle_key( $ip );
		$data = get_transient( $key );

		if ( ! is_array( $data ) ) {
			$data = array( 'attempts' => 0, 'locked_until' => 0 );
		}

		$data['attempts']++;

		if ( $data['attempts'] >= BC_RESET_MAX_ATTEMPTS ) {
			$data['locked_until'] = time() + BC_RESET_WINDOW_SECONDS;
		}

		set_transient( $key, $data, BC_RESET_WINDOW_SECONDS );
	}

	/**
	 * Check whether an account is inside its reset cooldown.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	private function is_account_cooling_down( int $user_id ): bool {
		return (bool) get_transient( $this->account_key( $user_id ) );
	}

	/**
	 * Redirect to the "check your email" confirmation and terminate.
	 *
	 * Mirrors the success path in wp-login.php exactly, so a suppressed request is
	 * indistinguishable from one that actually sent an email.
	 */
	private function redirect_to_confirmation(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Mirrors core's own handling.
		$redirect_to = ! empty( $_REQUEST['redirect_to'] )
			? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) )
			: 'wp-login.php?checkemail=confirm';

		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Send a 429 throttle response and terminate.
	 *
	 * Only reachable from wp-login.php, so an HTML response is always correct here.
	 *
	 * @param int $remaining Seconds remaining in the throttle window.
	 */
	private function send_throttle_response( int $remaining ): void {
		$minutes = (int) ceil( $remaining / 60 );

		status_header( 429 );
		header( "Retry-After: $remaining" );
		wp_die(
			"<h1>Access Denied</h1><p>Too many password reset requests. Try again in {$minutes} minute(s).</p>",
			'Too Many Requests',
			array( 'response' => 429 )
		);
	}

	/**
	 * Log a password reset event.
	 *
	 * @param string      $status Either 'sent' or 'blocked'.
	 * @param string|null $reason Block reason, or null for a sent event.
	 */
	private function log_event( string $status, ?string $reason ): void {
		if ( ! $this->logger ) {
			return;
		}

		$this->logger->log( array(
			'ip'           => $this->ip_resolver->get_client_ip(),
			'status'       => $status,
			'block_reason' => $reason,
			'form_plugin'  => 'password_reset',
			'page_url'     => $this->get_page_url(),
			'form_data'    => array( 'user_login' => $this->get_submitted_login() ),
		) );
	}

	/**
	 * Get the identifier submitted in the lost-password form.
	 *
	 * @return string Submitted username or email, or an empty string.
	 */
	private function get_submitted_login(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read-only, for logging.
		if ( empty( $_POST['user_login'] ) ) {
			return '';
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read-only, for logging.
		return sanitize_text_field( wp_unslash( $_POST['user_login'] ) );
	}

	/**
	 * Get the current request URL for logging.
	 *
	 * @return string Request URI, or an empty string.
	 */
	private function get_page_url(): string {
		if ( ! empty( $_SERVER['REQUEST_URI'] ) ) {
			return esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) );
		}

		return '';
	}
}
