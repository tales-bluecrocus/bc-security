<?php
/**
 * GitHub-based plugin auto-updater.
 *
 * Uses Plugin Update Checker to detect new releases on GitHub
 * and offer updates through the WordPress admin dashboard.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

class UpdateChecker {

	/**
	 * Register the update checker with GitHub releases.
	 */
	public function register(): void {
		if ( ! class_exists( PucFactory::class ) ) {
			return;
		}

		$checker = PucFactory::buildUpdateChecker(
			'https://github.com/tales-bluecrocus/bc-security/',
			BC_SECURITY_FILE,
			'bc-security'
		);

		$checker->setBranch( 'main' );
		$checker->getVcsApi()->enableReleaseAssets();

		// Ensure the extracted folder name matches the plugin slug.
		add_filter( 'upgrader_source_selection', function ( $source, $remote_source, $upgrader, $hook_extra ) {
			if ( ! isset( $hook_extra['plugin'] ) || plugin_basename( BC_SECURITY_FILE ) !== $hook_extra['plugin'] ) {
				return $source;
			}

			if ( basename( $source ) === 'bc-security' ) {
				return $source;
			}

			global $wp_filesystem;

			$corrected_source = trailingslashit( $remote_source ) . 'bc-security/';

			if ( $wp_filesystem->move( $source, $corrected_source ) ) {
				return $corrected_source;
			}

			return new \WP_Error( 'rename_failed', 'Could not rename the plugin folder during update.' );
		}, 10, 4 );
	}
}
