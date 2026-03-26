<?php
/**
 * Logs table — WP_List_Table subclass for displaying form submission logs.
 *
 * @package BcSecurity
 */

namespace BcSecurity;

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

class LogsTable extends \WP_List_Table {

	/**
	 * @var FormLogger
	 */
	private $logger;

	/**
	 * @param FormLogger $logger Form submission logger.
	 */
	public function __construct( FormLogger $logger ) {
		$this->logger = $logger;

		parent::__construct( array(
			'singular' => 'log',
			'plural'   => 'logs',
			'ajax'     => false,
		) );
	}

	/**
	 * Define table columns.
	 *
	 * @return array Column slug => Column label.
	 */
	public function get_columns(): array {
		return array(
			'created_at'   => 'Date',
			'ip'           => 'IP',
			'status'       => 'Status',
			'block_reason' => 'Reason',
			'form_plugin'  => 'Form Plugin',
			'page_url'     => 'Page URL',
		);
	}

	/**
	 * Define sortable columns.
	 *
	 * @return array Column slug => array( orderby value, default desc ).
	 */
	public function get_sortable_columns(): array {
		return array(
			'created_at' => array( 'created_at', true ),
		);
	}

	/**
	 * Prepare items for display — query data, set pagination.
	 */
	public function prepare_items(): void {
		$per_page = 25;

		$args = array(
			'per_page' => $per_page,
			'page'     => $this->get_pagenum(),
			'orderby'  => isset( $_GET['orderby'] ) ? sanitize_text_field( wp_unslash( $_GET['orderby'] ) ) : 'created_at',
			'order'    => isset( $_GET['order'] ) ? sanitize_text_field( wp_unslash( $_GET['order'] ) ) : 'DESC',
		);

		if ( ! empty( $_GET['status_filter'] ) ) {
			$args['status'] = sanitize_text_field( wp_unslash( $_GET['status_filter'] ) );
		}

		if ( ! empty( $_GET['s'] ) ) {
			$args['search'] = sanitize_text_field( wp_unslash( $_GET['s'] ) );
		}

		$this->items = $this->logger->get_logs( $args );
		$total_items = $this->logger->get_total( $args );

		$this->set_pagination_args( array(
			'total_items' => $total_items,
			'per_page'    => $per_page,
			'total_pages' => ceil( $total_items / $per_page ),
		) );

		$this->_column_headers = array(
			$this->get_columns(),
			array(),
			$this->get_sortable_columns(),
		);
	}

	/**
	 * Render the Date column.
	 *
	 * @param object $item Row data.
	 * @return string Formatted date.
	 */
	public function column_created_at( $item ): string {
		$utc_time   = $item->created_at;
		$local_time = get_date_from_gmt( $utc_time, 'Y-m-d H:i:s' );

		return esc_html( $local_time );
	}

	/**
	 * Render the IP column.
	 *
	 * @param object $item Row data.
	 * @return string IP address.
	 */
	public function column_ip( $item ): string {
		return esc_html( $item->ip );
	}

	/**
	 * Render the Status column with a colored badge.
	 *
	 * @param object $item Row data.
	 * @return string Status badge HTML.
	 */
	public function column_status( $item ): string {
		if ( $item->status === 'blocked' ) {
			return '<span style="background:#dc3232;color:#fff;padding:2px 8px;border-radius:3px;font-size:12px;">Blocked</span>';
		}

		return '<span style="background:#46b450;color:#fff;padding:2px 8px;border-radius:3px;font-size:12px;">Sent</span>';
	}

	/**
	 * Render the Reason column.
	 *
	 * @param object $item Row data.
	 * @return string Block reason or dash.
	 */
	public function column_block_reason( $item ): string {
		if ( empty( $item->block_reason ) ) {
			return '&mdash;';
		}

		return esc_html( $item->block_reason );
	}

	/**
	 * Render the Form Plugin column.
	 *
	 * @param object $item Row data.
	 * @return string Plugin name.
	 */
	public function column_form_plugin( $item ): string {
		$labels = array(
			'elementor'   => 'Elementor Pro',
			'cf7'         => 'Contact Form 7',
			'gravity'     => 'Gravity Forms',
			'formidable'  => 'Formidable',
		);

		$plugin = $item->form_plugin;

		return esc_html( isset( $labels[ $plugin ] ) ? $labels[ $plugin ] : $plugin );
	}

	/**
	 * Render the Page URL column.
	 *
	 * @param object $item Row data.
	 * @return string Linked URL.
	 */
	public function column_page_url( $item ): string {
		if ( empty( $item->page_url ) ) {
			return '&mdash;';
		}

		$url = esc_url( $item->page_url );

		// Show only the path portion for readability.
		$parsed = wp_parse_url( $item->page_url );
		$path   = isset( $parsed['path'] ) ? $parsed['path'] : '/';

		return '<a href="' . $url . '" target="_blank" rel="noopener">' . esc_html( $path ) . '</a>';
	}

	/**
	 * Render the status filter dropdown above the table.
	 *
	 * @param string $which Top or bottom position.
	 */
	protected function extra_tablenav( $which ): void {
		if ( $which !== 'top' ) {
			return;
		}

		$current_status = isset( $_GET['status_filter'] ) ? sanitize_text_field( wp_unslash( $_GET['status_filter'] ) ) : '';
		?>
		<div class="alignleft actions">
			<select name="status_filter">
				<option value="">All Statuses</option>
				<option value="sent" <?php selected( $current_status, 'sent' ); ?>>Sent</option>
				<option value="blocked" <?php selected( $current_status, 'blocked' ); ?>>Blocked</option>
			</select>
			<?php submit_button( 'Filter', '', 'filter_action', false ); ?>
		</div>
		<?php
	}

	/**
	 * Message displayed when no items are found.
	 */
	public function no_items(): void {
		echo 'No form submissions logged yet.';
	}
}
