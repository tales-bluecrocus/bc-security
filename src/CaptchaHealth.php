<?php
/**
 * Tracks whether CAPTCHA verification has been succeeding, to warn about keys that
 * stop working after they were tested — for example when Google retires them.
 *
 * Google reports a retired or wrong reCAPTCHA key exactly like a forged token, so
 * no single request can tell the difference. A streak of failures with no success
 * for an hour is the signal instead. It only ever drives an admin notice: a bot
 * flood looks identical, so nothing here may loosen verification. The verify path
 * writes to this class and never reads it.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class CaptchaHealth {

	/**
	 * Option holding per-pair health records.
	 */
	const OPTION = 'bc_security_captcha_health';

	/**
	 * Failures recorded per streak before writes stop, so a flood cannot turn into
	 * one database write per request.
	 */
	const CAP = 10;

	/**
	 * Failures required before the warning shows.
	 */
	const MIN_FAILS = 5;

	/**
	 * How long a streak must last with no success before the warning shows.
	 */
	const MIN_STREAK_SECONDS = 3600;

	/**
	 * Refresh last_success at most this often while things are healthy.
	 */
	const SUCCESS_REFRESH_SECONDS = 600;

	/**
	 * Record a failed verification.
	 *
	 * @param string $pair        'main' or 'v3'.
	 * @param string $fingerprint Fingerprint of the pair in use.
	 * @param string $code        What failed.
	 */
	public function failure( string $pair, string $fingerprint, string $code ): void {
		$all    = $this->all();
		$record = $this->record( $all, $pair, $fingerprint );

		if ( (int) $record['fails'] >= self::CAP ) {
			return;
		}

		if ( 0 === (int) $record['fails'] ) {
			$record['streak_start'] = time();
		}

		$record['fails']     = (int) $record['fails'] + 1;
		$record['last_code'] = $code;

		$all[ $pair ] = $record;
		update_option( self::OPTION, $all, true );
	}

	/**
	 * Record a successful verification.
	 *
	 * @param string $pair        'main' or 'v3'.
	 * @param string $fingerprint Fingerprint of the pair in use.
	 */
	public function success( string $pair, string $fingerprint ): void {
		$all     = $this->all();
		$record  = $this->record( $all, $pair, $fingerprint );
		$current = isset( $all[ $pair ]['fp'] ) && $all[ $pair ]['fp'] === $fingerprint;

		if ( $current && 0 === (int) $record['fails'] && time() - (int) $record['last_success'] < self::SUCCESS_REFRESH_SECONDS ) {
			return;
		}

		$record['fails']        = 0;
		$record['streak_start'] = 0;
		$record['last_success'] = time();
		$record['last_code']    = '';

		$all[ $pair ] = $record;
		update_option( self::OPTION, $all, true );
	}

	/**
	 * The failure record to warn about, if the pair looks broken.
	 *
	 * @param string $pair        'main' or 'v3'.
	 * @param string $fingerprint Fingerprint of the pair in use.
	 * @return array|null
	 */
	public function warning( string $pair, string $fingerprint ): ?array {
		$all = $this->all();

		if ( ! isset( $all[ $pair ]['fp'] ) || $all[ $pair ]['fp'] !== $fingerprint ) {
			return null;
		}

		$record = $this->record( $all, $pair, $fingerprint );

		if ( (int) $record['fails'] < self::MIN_FAILS ) {
			return null;
		}

		if ( time() - (int) $record['streak_start'] < self::MIN_STREAK_SECONDS ) {
			return null;
		}

		return $record;
	}

	/**
	 * The stored record for a pair, reset if the keys have changed since.
	 *
	 * @param array  $all         All records.
	 * @param string $pair        'main' or 'v3'.
	 * @param string $fingerprint Fingerprint of the pair in use.
	 * @return array
	 */
	private function record( array $all, string $pair, string $fingerprint ): array {
		$fresh = array(
			'fp'           => $fingerprint,
			'fails'        => 0,
			'streak_start' => 0,
			'last_success' => 0,
			'last_code'    => '',
		);

		if ( isset( $all[ $pair ] ) && is_array( $all[ $pair ] ) && isset( $all[ $pair ]['fp'] ) && $all[ $pair ]['fp'] === $fingerprint ) {
			return wp_parse_args( $all[ $pair ], $fresh );
		}

		return $fresh;
	}

	/**
	 * All stored records.
	 *
	 * @return array
	 */
	private function all(): array {
		$all = get_option( self::OPTION, array() );

		return is_array( $all ) ? $all : array();
	}
}
