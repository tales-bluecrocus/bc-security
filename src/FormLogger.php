<?php
/**
 * Form submission logger.
 *
 * Inserts and queries log entries in the bc_form_logs table.
 * Used by SpamFilter to record submissions and by AdminPage to display them.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

class FormLogger {

	/**
	 * Get the full table name with prefix.
	 *
	 * @return string Table name.
	 */
	private function table_name(): string {
		global $wpdb;

		return $wpdb->prefix . 'bc_form_logs';
	}

	/**
	 * Log a form submission.
	 *
	 * @param array $data {
	 *     Submission data.
	 *
	 *     @type string $ip           Client IP address.
	 *     @type string $status       'sent' or 'blocked'.
	 *     @type string $block_reason Reason for blocking, or null if sent.
	 *     @type string $form_plugin  Plugin identifier (elementor, cf7, gravity, formidable).
	 *     @type string $page_url     URL where the form was submitted.
	 *     @type array  $form_data    Form fields (name, email, message, etc.).
	 * }
	 */
	public function log( array $data ): void {
		global $wpdb;

		$wpdb->insert(
			$this->table_name(),
			array(
				'created_at'   => current_time( 'mysql', true ),
				'ip'           => sanitize_text_field( $data['ip'] ),
				'status'       => sanitize_text_field( $data['status'] ),
				'block_reason' => isset( $data['block_reason'] ) ? sanitize_text_field( $data['block_reason'] ) : null,
				'form_plugin'  => sanitize_text_field( $data['form_plugin'] ),
				'page_url'     => esc_url_raw( $data['page_url'] ),
				'form_data'    => wp_json_encode( $data['form_data'] ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Retrieve log entries with filtering, pagination, and sorting.
	 *
	 * @param array $args {
	 *     Query arguments.
	 *
	 *     @type string $status   Filter by status ('sent', 'blocked', or empty for all).
	 *     @type string $search   Search term matched against IP and block_reason.
	 *     @type int    $per_page Number of results per page. Default 25.
	 *     @type int    $page     Page number (1-based). Default 1.
	 *     @type string $orderby  Column to sort by. Default 'created_at'.
	 *     @type string $order    Sort direction ('ASC' or 'DESC'). Default 'DESC'.
	 * }
	 * @return array Array of row objects.
	 */
	public function get_logs( array $args = array() ): array {
		global $wpdb;

		$defaults = array(
			'status'   => '',
			'search'   => '',
			'per_page' => 25,
			'page'     => 1,
			'orderby'  => 'created_at',
			'order'    => 'DESC',
		);

		$args  = wp_parse_args( $args, $defaults );
		$table = $this->table_name();

		$where_clauses = array();
		$where_values  = array();

		if ( ! empty( $args['status'] ) ) {
			$where_clauses[] = 'status = %s';
			$where_values[]  = $args['status'];
		}

		if ( ! empty( $args['search'] ) ) {
			$where_clauses[] = '(ip LIKE %s OR block_reason LIKE %s)';
			$search_term     = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where_values[]  = $search_term;
			$where_values[]  = $search_term;
		}

		$where = '';
		if ( ! empty( $where_clauses ) ) {
			$where = 'WHERE ' . implode( ' AND ', $where_clauses );
		}

		$allowed_orderby = array( 'created_at', 'id', 'status', 'ip' );
		$orderby         = in_array( $args['orderby'], $allowed_orderby, true ) ? $args['orderby'] : 'created_at';
		$order           = strtoupper( $args['order'] ) === 'ASC' ? 'ASC' : 'DESC';

		$per_page = absint( $args['per_page'] );
		$offset   = ( absint( $args['page'] ) - 1 ) * $per_page;

		$sql = "SELECT * FROM {$table} {$where} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d";

		$query_values   = array_merge( $where_values, array( $per_page, $offset ) );
		$prepared_query = $wpdb->prepare( $sql, $query_values );

		return $wpdb->get_results( $prepared_query );
	}

	/**
	 * Get the total number of log entries matching the given filters.
	 *
	 * @param array $args {
	 *     Filter arguments (same as get_logs but pagination keys are ignored).
	 *
	 *     @type string $status Filter by status.
	 *     @type string $search Search term matched against IP and block_reason.
	 * }
	 * @return int Total row count.
	 */
	public function get_total( array $args = array() ): int {
		global $wpdb;

		$table = $this->table_name();

		$where_clauses = array();
		$where_values  = array();

		if ( ! empty( $args['status'] ) ) {
			$where_clauses[] = 'status = %s';
			$where_values[]  = $args['status'];
		}

		if ( ! empty( $args['search'] ) ) {
			$where_clauses[] = '(ip LIKE %s OR block_reason LIKE %s)';
			$search_term     = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where_values[]  = $search_term;
			$where_values[]  = $search_term;
		}

		$where = '';
		if ( ! empty( $where_clauses ) ) {
			$where = 'WHERE ' . implode( ' AND ', $where_clauses );
		}

		if ( ! empty( $where_values ) ) {
			return (int) $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} {$where}",
				$where_values
			) );
		}

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
	}

	/**
	 * Delete all log entries.
	 */
	public function clear_logs(): void {
		global $wpdb;

		$wpdb->query( "TRUNCATE TABLE {$this->table_name()}" );
	}
}
