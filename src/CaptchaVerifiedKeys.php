<?php
/**
 * Records which CAPTCHA key pairs have passed Test Keys on this host.
 *
 * A pair is only enforced once its fingerprint appears here. The newest few are
 * kept, so testing a candidate key without saving it never evicts the pair that is
 * currently working.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class CaptchaVerifiedKeys {

	/**
	 * Option holding the verified entries. Kept outside bc_security_settings so a
	 * settings save can never wipe it.
	 */
	const OPTION = 'bc_security_captcha_verified';

	/**
	 * How many verified pairs to remember.
	 */
	const MAX = 5;

	/**
	 * Check whether a fingerprint has passed Test Keys.
	 *
	 * @param string $fingerprint Pair fingerprint.
	 * @return bool
	 */
	public function is_verified( string $fingerprint ): bool {
		return null !== $this->find( $fingerprint );
	}

	/**
	 * When a fingerprint passed Test Keys.
	 *
	 * @param string $fingerprint Pair fingerprint.
	 * @return int Unix time, or 0 if not verified.
	 */
	public function time_for( string $fingerprint ): int {
		$entry = $this->find( $fingerprint );

		return $entry ? (int) $entry['time'] : 0;
	}

	/**
	 * Record a pair as verified on this host.
	 *
	 * @param string $pair        'main' or 'v3'.
	 * @param string $fingerprint Pair fingerprint.
	 * @param string $host        Host it was verified on.
	 */
	public function mark( string $pair, string $fingerprint, string $host ): void {
		$entries = array();

		foreach ( $this->all() as $entry ) {
			if ( isset( $entry['fp'] ) && $entry['fp'] !== $fingerprint ) {
				$entries[] = $entry;
			}
		}

		array_unshift( $entries, array(
			'fp'   => $fingerprint,
			'pair' => $pair,
			'host' => $host,
			'time' => time(),
		) );

		update_option( self::OPTION, array_slice( $entries, 0, self::MAX ), true );
	}

	/**
	 * Find an entry by fingerprint.
	 *
	 * @param string $fingerprint Pair fingerprint.
	 * @return array|null
	 */
	private function find( string $fingerprint ): ?array {
		if ( '' === $fingerprint ) {
			return null;
		}

		foreach ( $this->all() as $entry ) {
			if ( isset( $entry['fp'] ) && hash_equals( (string) $entry['fp'], $fingerprint ) ) {
				return $entry;
			}
		}

		return null;
	}

	/**
	 * All stored entries.
	 *
	 * @return array
	 */
	private function all(): array {
		$entries = get_option( self::OPTION, array() );

		if ( ! is_array( $entries ) ) {
			return array();
		}

		return array_values( array_filter( $entries, 'is_array' ) );
	}
}
