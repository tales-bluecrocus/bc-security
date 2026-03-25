<?php
/**
 * Brute force protection — rate-limits login attempts across all authentication vectors.
 *
 * Covers wp-login.php, XML-RPC (disabled entirely), and JWT Auth endpoints.
 * Uses WordPress transients for lockout state per IP.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class BruteForce {

	/**
	 * @var IpResolver
	 */
	private $ip_resolver;

	/**
	 * @param IpResolver $ip_resolver IP detection dependency.
	 */
	public function __construct( IpResolver $ip_resolver ) {
		$this->ip_resolver = $ip_resolver;
	}

	/**
	 * Register all WordPress hooks for brute force protection.
	 */
	public function register(): void {
		// Vector A: wp-login.php
		add_action( 'login_init', array( $this, 'check_lockout_on_login' ) );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ) );
		add_action( 'wp_login', array( $this, 'on_login_success' ) );

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
		if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
			return;
		}

		$ip        = $this->ip_resolver->get_client_ip();
		$remaining = $this->is_locked_out( $ip );

		if ( $remaining > 0 ) {
			$this->send_lockout_response( $remaining );
		}
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
	 * @param mixed  $user     Null, WP_User, or WP_Error.
	 * @param string $username Provided username.
	 * @param string $password Provided password.
	 * @return mixed|\WP_Error Original value or lockout error.
	 */
	public function check_lockout_on_authenticate( $user, $username, $password ) {
		if ( empty( $username ) || empty( $password ) ) {
			return $user;
		}

		$ip        = $this->ip_resolver->get_client_ip();
		$remaining = $this->is_locked_out( $ip );

		if ( $remaining > 0 ) {
			return new \WP_Error(
				'too_many_requests',
				'Too many failed login attempts. Try again in ' . ceil( $remaining / 60 ) . ' minute(s).'
			);
		}

		return $user;
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
