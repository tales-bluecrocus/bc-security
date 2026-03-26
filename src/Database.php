<?php
/**
 * Database table creation and migration.
 *
 * Creates and updates the bc_form_logs table used by the spam protection feature.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class Database {

	/**
	 * Current database schema version.
	 */
	const DB_VERSION = '1.0.0';

	/**
	 * Option name for tracking the installed DB version.
	 */
	const VERSION_OPTION = 'bc_security_db_version';

	/**
	 * Create or update tables if the schema version has changed.
	 *
	 * Called on plugins_loaded and register_activation_hook.
	 */
	public function maybe_create_tables(): void {
		$installed_version = get_option( self::VERSION_OPTION, '' );

		if ( $installed_version === self::DB_VERSION ) {
			return;
		}

		$this->create_form_logs_table();
		update_option( self::VERSION_OPTION, self::DB_VERSION );
	}

	/**
	 * Create the bc_form_logs table using dbDelta.
	 */
	private function create_form_logs_table(): void {
		global $wpdb;

		$table_name      = $wpdb->prefix . 'bc_form_logs';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL,
			ip VARCHAR(45) NOT NULL,
			status VARCHAR(10) NOT NULL,
			block_reason VARCHAR(100) DEFAULT NULL,
			form_plugin VARCHAR(50) NOT NULL,
			page_url VARCHAR(255) NOT NULL,
			form_data TEXT NOT NULL,
			PRIMARY KEY  (id),
			KEY idx_created_at (created_at),
			KEY idx_status (status)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}
}
