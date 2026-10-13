<?php
/**
 * One-time addition of new default keywords to a site's saved keyword list.
 *
 * SpamFilter::DEFAULT_KEYWORDS only applies until the settings page is first saved;
 * after that the site keeps its own copy, which a plugin update never touches. This
 * appends the keywords added since, once per revision, so a keyword an admin later
 * deletes stays deleted.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class KeywordMigration {

	/**
	 * Option recording which keyword additions this site already has.
	 */
	const REV_OPTION = 'bc_security_keywords_rev';

	/**
	 * Current revision. Raise it whenever ADDED changes.
	 */
	const REV = 1;

	/**
	 * Keywords added to SpamFilter::DEFAULT_KEYWORDS in this revision.
	 *
	 * "cryptocurrency" is older, but keywords now match whole words only, so a saved
	 * list holding just "crypto" would stop catching it.
	 */
	const ADDED = array(
		'rank higher on google',
		'could rank higher',
		'directoryinspector.com',
		'trezor suite',
		'trezor-suite-us.com',
		'cryptocurrency',
		'cold outreach',
		'email outreach',
		'outreach campaign',
		'b2b data',
		'freeb2bdata',
		'companyscout',
		'ultraleadgeneration.com',
		'blastleadgeneration',
		'redesign your website',
		'ai agent',
		'dandyaisoftware.com',
		'virtual assistant',
		'toptalentvas.com',
		'proxy service',
		'zero downtime',
	);

	/**
	 * Add the new keywords once. Runs at plugin load, before the settings sanitizer
	 * is attached, so it writes raw values. The revision is written last: a run
	 * interrupted part-way simply runs again, and adds nothing twice.
	 *
	 * A site that never saved its settings is already on the defaults, and a list
	 * an admin emptied on purpose is left empty.
	 */
	public function maybe_migrate(): void {
		if ( (int) get_option( self::REV_OPTION, 0 ) >= self::REV ) {
			return;
		}

		$settings = get_option( 'bc_security_settings', null );

		if ( is_array( $settings ) && ! empty( $settings['blocked_keywords'] ) && is_array( $settings['blocked_keywords'] ) ) {
			$have = array();

			foreach ( $settings['blocked_keywords'] as $keyword ) {
				if ( is_string( $keyword ) ) {
					$have[ strtolower( trim( $keyword ) ) ] = true;
				}
			}

			$missing = array();

			foreach ( self::ADDED as $keyword ) {
				if ( ! isset( $have[ $keyword ] ) ) {
					$missing[] = $keyword;
				}
			}

			if ( $missing ) {
				$settings['blocked_keywords'] = array_merge( array_values( $settings['blocked_keywords'] ), $missing );
				update_option( 'bc_security_settings', $settings );
			}
		}

		update_option( self::REV_OPTION, self::REV, true );
	}
}
