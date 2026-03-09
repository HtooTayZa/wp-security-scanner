<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) exit;

global $wpdb;
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wpss_results" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wpss_scans" );
delete_option( 'wpss_db_version' );
delete_option( 'wpss_anthropic_api_key' );
