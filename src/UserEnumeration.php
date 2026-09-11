<?php
/**
 * User enumeration protection — blocks discovery of valid usernames.
 *
 * Covers the REST API users endpoints, author archives (?author=N and
 * /author/slug/), the author link in oEmbed data, WordPress's users sitemap, and
 * login error messages.
 *
 * Every vector must give the same answer whether or not the account exists: a
 * different answer for a real name is itself the leak.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class UserEnumeration {

	/**
	 * Core authentication error codes that name or confirm an account.
	 *
	 * invalid_username / invalid_email say the account does not exist;
	 * incorrect_password names the account it does exist for.
	 *
	 * @var array
	 */
	const LOGIN_ENUMERATION_CODES = array( 'invalid_username', 'invalid_email', 'incorrect_password' );

	/**
	 * Register all WordPress hooks for user enumeration protection.
	 */
	public function register(): void {
		add_filter( 'rest_endpoints', array( $this, 'remove_users_endpoint' ) );
		add_action( 'template_redirect', array( $this, 'redirect_author_archives' ) );
		add_action( 'parse_request', array( $this, 'block_author_query' ) );
		add_filter( 'oembed_response_data', array( $this, 'remove_oembed_author_url' ) );
		add_filter( 'wp_sitemaps_add_provider', array( $this, 'remove_users_sitemap' ), 10, 2 );

		// After core's password check (20) and the brute force check (30).
		add_filter( 'authenticate', array( $this, 'genericize_login_errors' ), 40 );
	}

	/**
	 * The one login error shown for any wrong username, email or password.
	 *
	 * Uses core's incorrect_password code so the form shakes the same way for
	 * every failure — a shake for one case and not the other would be a tell too.
	 *
	 * @return \WP_Error
	 */
	public static function login_error(): \WP_Error {
		return new \WP_Error(
			'incorrect_password',
			'<strong>Error:</strong> The username or password you entered is incorrect. <a href="' . esc_url( wp_lostpassword_url() ) . '">Lost your password?</a>'
		);
	}

	/**
	 * Remove /wp/v2/users endpoints for unauthenticated requests.
	 *
	 * @param array $endpoints Registered REST endpoints.
	 * @return array Filtered endpoints.
	 */
	public function remove_users_endpoint( array $endpoints ): array {
		if ( ! is_user_logged_in() ) {
			unset( $endpoints['/wp/v2/users'] );
			unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		}

		return $endpoints;
	}

	/**
	 * Redirect author archive requests to the homepage.
	 */
	public function redirect_author_archives(): void {
		if ( is_author() ) {
			wp_redirect( home_url(), 301 );
			exit;
		}
	}

	/**
	 * Redirect every author lookup before the query runs.
	 *
	 * Covers ?author=N and /author/slug/ (the author_name query var) alike. Left to
	 * WordPress, a made-up slug gets a 404 while a real one reaches the archive
	 * redirect — two different answers that confirm which names exist.
	 *
	 * @param \WP $wp WordPress request object.
	 */
	public function block_author_query( \WP $wp ): void {
		if ( is_admin() || is_user_logged_in() ) {
			return;
		}

		if ( isset( $wp->query_vars['author'] ) || isset( $wp->query_vars['author_name'] ) ) {
			wp_redirect( home_url(), 301 );
			exit;
		}
	}

	/**
	 * Drop the author archive link from oEmbed data.
	 *
	 * The link carries the author's slug, which WordPress builds from the login
	 * (webdev@example.com becomes webdevexample-com). The author's display name is
	 * kept: it is already shown on the post itself, and clients want the credit.
	 *
	 * @param array|mixed $data oEmbed response data.
	 * @return array|mixed
	 */
	public function remove_oembed_author_url( $data ) {
		if ( is_array( $data ) ) {
			unset( $data['author_url'] );
		}

		return $data;
	}

	/**
	 * Remove WordPress's built-in users sitemap.
	 *
	 * It lists every author archive URL, slugs included — and those archives only
	 * redirect to the homepage anyway. SEO plugins' own author sitemaps are theirs
	 * to switch off.
	 *
	 * @param mixed  $provider Sitemap provider.
	 * @param string $name     Provider name.
	 * @return mixed Provider, or false to remove it.
	 */
	public function remove_users_sitemap( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * Replace login errors that confirm an account with one generic error.
	 *
	 * Only core's own codes are replaced, and only when they are the whole error:
	 * lockouts, the CAPTCHA check, two-factor prompts and other plugins' messages
	 * pass through untouched.
	 *
	 * @param mixed $user Null, WP_User, or WP_Error.
	 * @return mixed
	 */
	public function genericize_login_errors( $user ) {
		if ( ! is_wp_error( $user ) ) {
			return $user;
		}

		$codes = $user->get_error_codes();

		if ( empty( $codes ) || array_diff( $codes, self::LOGIN_ENUMERATION_CODES ) ) {
			return $user;
		}

		return self::login_error();
	}
}
