<?php
/**
 * User enumeration protection — blocks discovery of valid usernames.
 *
 * Covers REST API /wp/v2/users, author archives, and ?author=N query parameter.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class UserEnumeration {

	/**
	 * Register all WordPress hooks for user enumeration protection.
	 */
	public function register(): void {
		add_filter( 'rest_endpoints', array( $this, 'remove_users_endpoint' ) );
		add_action( 'template_redirect', array( $this, 'redirect_author_archives' ) );
		add_action( 'parse_request', array( $this, 'block_author_query' ) );
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
	 * Block ?author=N enumeration before the query runs.
	 *
	 * @param \WP $wp WordPress request object.
	 */
	public function block_author_query( \WP $wp ): void {
		if ( ! is_admin() && isset( $wp->query_vars['author'] ) && ! is_user_logged_in() ) {
			wp_redirect( home_url(), 301 );
			exit;
		}
	}
}
