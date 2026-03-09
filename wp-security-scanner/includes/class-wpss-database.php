<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSS_Database {

    const TABLE_SCANS   = 'wpss_scans';
    const TABLE_RESULTS = 'wpss_results';

    public static function install() {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();
        $scans   = $wpdb->prefix . self::TABLE_SCANS;
        $results = $wpdb->prefix . self::TABLE_RESULTS;

        $sql = "
        CREATE TABLE IF NOT EXISTS {$scans} (
            id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            target_url    VARCHAR(500)  NOT NULL,
            status        VARCHAR(20)   NOT NULL DEFAULT 'pending',
            risk_score    TINYINT       NOT NULL DEFAULT 0,
            created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at  DATETIME      NULL,
            ai_summary    LONGTEXT      NULL
        ) {$charset};

        CREATE TABLE IF NOT EXISTS {$results} (
            id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            scan_id       BIGINT UNSIGNED NOT NULL,
            test_type     VARCHAR(50)  NOT NULL,
            severity      VARCHAR(20)  NOT NULL DEFAULT 'info',
            title         VARCHAR(255) NOT NULL,
            description   TEXT         NOT NULL,
            evidence      TEXT         NULL,
            remediation   TEXT         NULL,
            ai_analysis   LONGTEXT     NULL,
            created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX (scan_id),
            INDEX (severity)
        ) {$charset};
        ";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
        update_option( 'wpss_db_version', WPSS_VERSION );
    }

    public static function uninstall() {
        // Keep data on deactivation; only clean on full uninstall via uninstall.php
    }

    public static function create_scan( $url ) {
        global $wpdb;
        $wpdb->insert(
            $wpdb->prefix . self::TABLE_SCANS,
            array( 'target_url' => esc_url_raw( $url ), 'status' => 'running' ),
            array( '%s', '%s' )
        );
        return $wpdb->insert_id;
    }

    public static function save_result( $scan_id, $data ) {
        global $wpdb;
        $wpdb->insert(
            $wpdb->prefix . self::TABLE_RESULTS,
            array(
                'scan_id'     => $scan_id,
                'test_type'   => sanitize_text_field( $data['test_type'] ),
                'severity'    => sanitize_text_field( $data['severity'] ),
                'title'       => sanitize_text_field( $data['title'] ),
                'description' => wp_kses_post( $data['description'] ),
                'evidence'    => isset( $data['evidence'] ) ? sanitize_textarea_field( $data['evidence'] ) : '',
                'remediation' => isset( $data['remediation'] ) ? wp_kses_post( $data['remediation'] ) : '',
                'ai_analysis' => isset( $data['ai_analysis'] ) ? $data['ai_analysis'] : '',
            ),
            array( '%d','%s','%s','%s','%s','%s','%s','%s' )
        );
        return $wpdb->insert_id;
    }

    public static function complete_scan( $scan_id, $risk_score, $ai_summary = '' ) {
        global $wpdb;
        $wpdb->update(
            $wpdb->prefix . self::TABLE_SCANS,
            array(
                'status'       => 'completed',
                'risk_score'   => $risk_score,
                'completed_at' => current_time( 'mysql' ),
                'ai_summary'   => $ai_summary,
            ),
            array( 'id' => $scan_id ),
            array( '%s','%d','%s','%s' ),
            array( '%d' )
        );
    }

    public static function get_scan( $scan_id ) {
        global $wpdb;
        return $wpdb->get_row(
            $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}" . self::TABLE_SCANS . " WHERE id = %d", $scan_id )
        );
    }

    public static function get_results( $scan_id ) {
        global $wpdb;
        return $wpdb->get_results(
            $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}" . self::TABLE_RESULTS . " WHERE scan_id = %d ORDER BY FIELD(severity,'critical','high','medium','low','info')", $scan_id )
        );
    }

    public static function get_recent_scans( $limit = 10 ) {
        global $wpdb;
        return $wpdb->get_results(
            $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}" . self::TABLE_SCANS . " ORDER BY created_at DESC LIMIT %d", $limit )
        );
    }
}
