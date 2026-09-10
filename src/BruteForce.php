<?php
/**
 * Brute force protection — rate-limits login attempts across all authentication vectors.
 *
 * Covers wp-login.php, XML-RPC (disabled entirely), and JWT Auth endpoints.
 * Uses WordPress transients for lockout state per IP.
 *
 * Once an IP passes BC_MAX_ATTEMPTS, wp-login.php offers an escape hatch instead of
 * a flat 15-minute lockout, provided the CAPTCHA keys have passed Test Keys: the
 * sign-in form shows a checkbox, and each attempt must pass it as well as the
 * password. Normal sign-ins never see it or load the provider's script, so keys that
 * break later can never lock anyone out of the dashboard. Everywhere else (JWT,
 * WooCommerce and other front-end logins), and whenever CAPTCHA is not active, the
 * lockout applies exactly as before.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class BruteForce {

	/**
	 * wp-login.php actions that are not the sign-in form.
	 *
	 * @var array
	 */
	private static $non_login_actions = array(
		'postpass',
		'logout',
		'lostpassword',
		'retrievepassword',
		'resetpass',
		'rp',
		'register',
		'confirmaction',
		'confirm_admin_email',
	);

	/**
	 * @var IpResolver
	 */
	private $ip_resolver;

	/**
	 * @var CaptchaProvider|null
	 */
	private $captcha;

	/**
	 * True once login_init has fired, i.e. this request is wp-login.php.
	 *
	 * @var bool
	 */
	private $on_wp_login = false;

	/**
	 * @param IpResolver           $ip_resolver IP detection dependency.
	 * @param CaptchaProvider|null $captcha     Optional CAPTCHA provider.
	 */
	public function __construct( IpResolver $ip_resolver, ?CaptchaProvider $captcha = null ) {
		$this->ip_resolver = $ip_resolver;
		$this->captcha     = $captcha;
	}

	/**
	 * Register all WordPress hooks for brute force protection.
	 */
	public function register(): void {
		// Vector A: wp-login.php
		add_action( 'login_init', array( $this, 'check_lockout_on_login' ) );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ) );
		add_action( 'wp_login', array( $this, 'on_login_success' ) );

		// Escape hatch: shown only to flagged IPs, on the sign-in form.
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_challenge' ) );
		add_action( 'login_form', array( $this, 'render_login_challenge' ) );
		add_action( 'login_footer', array( $this, 'print_login_challenge_js' ) );
		add_filter( 'login_message', array( $this, 'login_challenge_message' ) );
		add_filter( 'shake_error_codes', array( $this, 'add_shake_error_code' ) );

		// Vector B: XML-RPC — disabled entirely
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'xmlrpc_methods', array( $this, 'remove_xmlrpc_auth_methods' ) );

		// Vector C: JWT Auth endpoint
		add_action( 'rest_api_init', array( $this, 'register_rest_hooks' ) );
		add_filter( 'jwt_auth_token_before_dispatch', array( $this, 'on_jwt_auth_result' ), 10, 2 );

		// Shared: authenticate filter covers wp-login + JWT
		add_filter( 'authenticate', array( $this, 'check_lockout_on_authenticate' ), 30, 3 );
	}

	/**
	 * Block locked-out IPs before wp-login.php processes the POST.
	 */
	public function check_lockout_on_login(): void {
		$this->on_wp_login = true;

		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
			return;
		}

		$remaining = $this->is_locked_out( $this->ip_resolver->get_client_ip() );

		if ( $remaining <= 0 ) {
			return;
		}

		// Escape hatch: a sign-in POST carrying a CAPTCHA token goes on to the
		// authenticate filter, where the token is verified. Everything else is
		// stopped here as before, with no password hashing and no database write.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Presence check only; verified in authenticate.
		if ( $this->challenge_active() && $this->is_login_action() && ! empty( $_POST[ CaptchaProvider::TOKEN_FIELD ] ) ) {
			return;
		}

		$this->send_lockout_response( $remaining );
	}

	/**
	 * Record a failed login attempt.
	 */
	public function on_login_failed(): void {
		$this->record_failed_attempt( $this->ip_resolver->get_client_ip() );
	}

	/**
	 * Clear failed attempts on successful login.
	 */
	public function on_login_success(): void {
		$this->clear_attempts( $this->ip_resolver->get_client_ip() );
	}

	/**
	 * Remove authentication-related XML-RPC methods.
	 *
	 * @param array $methods XML-RPC methods.
	 * @return array Filtered methods.
	 */
	public function remove_xmlrpc_auth_methods( array $methods ): array {
		unset( $methods['wp.getUsersBlogs'] );
		unset( $methods['wp.getAuthors'] );
		unset( $methods['wp.getUsers'] );

		return $methods;
	}

	/**
	 * Register REST API hooks for JWT lockout checking.
	 */
	public function register_rest_hooks(): void {
		add_filter( 'rest_pre_dispatch', array( $this, 'check_lockout_on_jwt' ), 10, 3 );
	}

	/**
	 * Check lockout on JWT token endpoint.
	 *
	 * @param mixed            $result  Response to replace the requested one.
	 * @param \WP_REST_Server  $server  REST server instance.
	 * @param \WP_REST_Request $request REST request.
	 * @return mixed|\WP_Error Original result or lockout error.
	 */
	public function check_lockout_on_jwt( $result, $server, $request ) {
		if ( $request->get_route() !== '/jwt-auth/v1/token' || $request->get_method() !== 'POST' ) {
			return $result;
		}

		$ip        = $this->ip_resolver->get_client_ip();
		$remaining = $this->is_locked_out( $ip );

		if ( $remaining > 0 ) {
			return new \WP_Error(
				'too_many_requests',
				'Too many failed login attempts. Try again in ' . ceil( $remaining / 60 ) . ' minute(s).',
				array( 'status' => 429 )
			);
		}

		return $result;
	}

	/**
	 * Handle JWT authentication result — record failure or clear on success.
	 *
	 * @param mixed $response JWT response data.
	 * @param mixed $user     WP_User on success, WP_Error on failure.
	 * @return mixed Unmodified response.
	 */
	public function on_jwt_auth_result( $response, $user ) {
		if ( is_wp_error( $user ) ) {
			$this->record_failed_attempt( $this->ip_resolver->get_client_ip() );
		} else {
			$this->clear_attempts( $this->ip_resolver->get_client_ip() );
		}

		return $response;
	}

	/**
	 * Check lockout during the authenticate filter (covers wp-login + JWT).
	 *
	 * Runs at priority 30, after core's password check at 20 — which discards any
	 * error handed to it, so an earlier priority could not stop anything.
	 *
	 * @param mixed  $user     Null, WP_User, or WP_Error.
	 * @param string $username Provided username.
	 * @param string $password Provided password.
	 * @return mixed|\WP_Error Original value or lockout error.
	 */
	public function check_lockout_on_authenticate( $user, $username, $password ) {
		if ( empty( $username ) || empty( $password ) ) {
			return $user;
		}

		$remaining = $this->is_locked_out( $this->ip_resolver->get_client_ip() );

		if ( $remaining > 0 ) {
			// JWT, WooCommerce and other logins, or CAPTCHA not active: the lockout.
			if ( ! $this->on_wp_login || ! $this->challenge_active() ) {
				return $this->lockout_error( $remaining );
			}

			$result = $this->captcha->verify_pair( 'main' );

			// The provider could not be reached: fall back to the lockout rather
			// than letting a flagged IP straight through.
			if ( isset( $result['reason'] ) && 'captcha_unavailable' === $result['reason'] ) {
				return $this->lockout_error( $remaining );
			}

			// Same message whether or not the password was right, so a failed
			// check reveals nothing about the password.
			if ( empty( $result['success'] ) ) {
				return new \WP_Error(
					'bc_captcha_required',
					'<strong>Error:</strong> Please complete the security check and try again.'
				);
			}

			// Check passed: the password verdict in $user stands. On success
			// wp_login clears the counter; on failure wp_login_failed adds to it.
		}

		// Block non-existent usernames immediately — kills distributed brute force.
		// No explicit record_failed_attempt() here: core fires wp_login_failed for
		// this error, and counting it here as well charged two attempts per guess.
		if ( ! username_exists( $username ) && ! email_exists( $username ) ) {
			return new \WP_Error(
				'authentication_failed',
				'<strong>Error:</strong> The username or password you entered is incorrect.'
			);
		}

		return $user;
	}

	/**
	 * Enqueue the checkbox script for a flagged IP on the sign-in form.
	 */
	public function enqueue_login_challenge(): void {
		if ( $this->show_challenge() ) {
			$this->captcha->enqueue_widget_login();
		}
	}

	/**
	 * Print the checkbox inside the sign-in form for a flagged IP.
	 */
	public function render_login_challenge(): void {
		if ( $this->show_challenge() ) {
			$this->captcha->print_widget_container();
		}
	}

	/**
	 * Print the checkbox script in the login footer for a flagged IP.
	 */
	public function print_login_challenge_js(): void {
		if ( $this->show_challenge() ) {
			$this->captcha->print_widget_js( 'login' );
		}
	}

	/**
	 * Explain the checkbox above the sign-in form.
	 *
	 * @param string $message Existing login message.
	 * @return string
	 */
	public function login_challenge_message( $message ) {
		if ( ! $this->show_challenge() ) {
			return $message;
		}

		return $message . '<p class="message">There have been several unsuccessful sign-in attempts from your connection. Please complete the security check below to continue.</p>';
	}

	/**
	 * Shake the login form on a failed check, like any other login error.
	 *
	 * @param array $codes Error codes that shake the form.
	 * @return array
	 */
	public function add_shake_error_code( $codes ) {
		$codes   = is_array( $codes ) ? $codes : array();
		$codes[] = 'bc_captcha_required';

		return $codes;
	}

	/**
	 * Check whether the escape hatch is available: verified main keys and the
	 * setting switched on.
	 *
	 * @return bool
	 */
	private function challenge_active(): bool {
		return null !== $this->captcha && $this->captcha->is_login_challenge_active();
	}

	/**
	 * Check whether to show the checkbox on this page.
	 *
	 * Evaluated while the page renders, after wp-login.php has processed the POST,
	 * so the attempt that just crossed the limit already counts.
	 *
	 * @return bool
	 */
	private function show_challenge(): bool {
		return $this->on_wp_login
			&& $this->challenge_active()
			&& $this->is_login_action()
			&& $this->is_locked_out( $this->ip_resolver->get_client_ip() ) > 0;
	}

	/**
	 * Check whether this wp-login.php request is the sign-in form.
	 *
	 * wp-login.php treats unknown actions as 'login'.
	 *
	 * @return bool
	 */
	private function is_login_action(): bool {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Routing only.
		if ( isset( $_GET['key'] ) ) {
			return false;
		}

		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
		// phpcs:enable

		return ! in_array( $action, self::$non_login_actions, true );
	}

	/**
	 * The lockout error returned from the authenticate filter.
	 *
	 * @param int $remaining Seconds remaining in lockout.
	 * @return \WP_Error
	 */
	private function lockout_error( int $remaining ): \WP_Error {
		return new \WP_Error(
			'too_many_requests',
			'Too many failed login attempts. Try again in ' . ceil( $remaining / 60 ) . ' minute(s).'
		);
	}

	/**
	 * Get the transient key for a given IP.
	 *
	 * @param string $ip Client IP address.
	 * @return string Transient key.
	 */
	private function transient_key( string $ip ): string {
		return 'bc_lockout_' . md5( $ip );
	}

	/**
	 * Check if an IP is currently locked out.
	 *
	 * @param string $ip Client IP address.
	 * @return int Remaining lockout seconds, or 0 if not locked out.
	 */
	private function is_locked_out( string $ip ): int {
		$data = get_transient( $this->transient_key( $ip ) );

		if ( ! is_array( $data ) ) {
			return 0;
		}

		if ( $data['attempts'] >= BC_MAX_ATTEMPTS ) {
			return max( 0, $data['locked_until'] - time() );
		}

		return 0;
	}

	/**
	 * Record a failed login attempt for an IP.
	 *
	 * Once over the limit, the lockout is rewritten at most once a minute, so bots
	 * sending junk tokens through the escape hatch cannot cause a write per request.
	 *
	 * @param string $ip Client IP address.
	 */
	private function record_failed_attempt( string $ip ): void {
		$key  = $this->transient_key( $ip );
		$data = get_transient( $key );

		if ( ! is_array( $data ) ) {
			$data = array( 'attempts' => 0, 'locked_until' => 0 );
		}

		$data['attempts']++;

		if ( $data['attempts'] >= BC_MAX_ATTEMPTS ) {
			if ( $data['attempts'] > BC_MAX_ATTEMPTS && $data['locked_until'] - time() > BC_LOCKOUT_SECONDS - 60 ) {
				return;
			}

			$data['locked_until'] = time() + BC_LOCKOUT_SECONDS;
		}

		set_transient( $key, $data, BC_LOCKOUT_SECONDS );
	}

	/**
	 * Clear failed attempts for an IP.
	 *
	 * @param string $ip Client IP address.
	 */
	private function clear_attempts( string $ip ): void {
		delete_transient( $this->transient_key( $ip ) );
	}

	/**
	 * Send a locked-out HTTP response and terminate.
	 *
	 * @param int $remaining Seconds remaining in lockout.
	 */
	private function send_lockout_response( int $remaining ): void {
		$minutes = (int) ceil( $remaining / 60 );

		if ( wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || $this->is_xmlrpc_request() ) {
			status_header( 429 );
			header( 'Content-Type: application/json; charset=utf-8' );
			header( "Retry-After: $remaining" );
			wp_die(
				wp_json_encode( array(
					'code'    => 'too_many_requests',
					'message' => "Too many failed login attempts. Try again in {$minutes} minute(s).",
					'data'    => array( 'status' => 429 ),
				) ),
				'Too Many Requests',
				array( 'response' => 429 )
			);
		}

		// HTML response for wp-login.php.
		status_header( 429 );
		header( "Retry-After: $remaining" );

		if ( $this->challenge_active() && $this->is_login_action() ) {
			wp_die(
				'<h1>Access Denied</h1><p>Too many failed login attempts. <a href="' . esc_url( wp_login_url() ) . '">Go back to the sign-in page</a>, complete the security check, and try again.</p>',
				'Too Many Requests',
				array( 'response' => 429 )
			);
		}

		wp_die(
			"<h1>Access Denied</h1><p>Too many failed login attempts. Try again in {$minutes} minute(s).</p>",
			'Too Many Requests',
			array( 'response' => 429 )
		);
	}

	/**
	 * Check if the current request is an XML-RPC request.
	 *
	 * @return bool
	 */
	private function is_xmlrpc_request(): bool {
		return defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST;
	}
}
