<?php
/**
 * Resolves the real client IP address behind proxies.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class IpResolver {

	/**
	 * Get the client IP address.
	 *
	 * Checks proxy headers first (X-Forwarded-For, X-Real-IP),
	 * then falls back to REMOTE_ADDR.
	 *
	 * @return string Valid IP address or '0.0.0.0' as fallback.
	 */
	public function get_client_ip(): string {
		$headers = array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' );

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip = explode( ',', $_SERVER[ $header ] )[0];
				$ip = trim( $ip );

				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		return '0.0.0.0';
	}
}
