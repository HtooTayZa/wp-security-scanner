<?php
/**
 * Plugin Name: WP Security Scanner Pro
 * Plugin URI:  https://github.com/your-repo/wp-security-scanner
 * Description: Advanced WordPress security scanner with AI-powered vulnerability analysis. Tests XSS, SQL Injection, SSL/TLS, Security Headers, and performs automated pen testing.
 * Version:     1.0.0
 * Author:      Security Scanner Pro
 * License:     GPL-2.0+
 * Text Domain: wp-security-scanner
 */

if ( ! defined( 'ABSPATH' ) ) exit;

define( 'WPSS_VERSION',     '1.0.0' );
define( 'WPSS_PLUGIN_DIR',  plugin_dir_path( __FILE__ ) );
define( 'WPSS_PLUGIN_URL',  plugin_dir_url( __FILE__ ) );
define( 'WPSS_PLUGIN_FILE', __FILE__ );

// Load core files
require_once WPSS_PLUGIN_DIR . 'includes/class-wpss-database.php';
require_once WPSS_PLUGIN_DIR . 'includes/class-wpss-scanner.php';
require_once WPSS_PLUGIN_DIR . 'includes/class-wpss-tests-xss.php';
require_once WPSS_PLUGIN_DIR . 'includes/class-wpss-tests-sqli.php';
require_once WPSS_PLUGIN_DIR . 'includes/class-wpss-tests-ssl.php';
require_once WPSS_PLUGIN_DIR . 'includes/class-wpss-tests-headers.php';
require_once WPSS_PLUGIN_DIR . 'includes/class-wpss-tests-pentest.php';
require_once WPSS_PLUGIN_DIR . 'includes/class-wpss-ai-analyzer.php';
require_once WPSS_PLUGIN_DIR . 'includes/class-wpss-report.php';
require_once WPSS_PLUGIN_DIR . 'admin/class-wpss-admin.php';

register_activation_hook( __FILE__, array( 'WPSS_Database', 'install' ) );
register_deactivation_hook( __FILE__, array( 'WPSS_Database', 'uninstall' ) );

add_action( 'plugins_loaded', function() {
    WPSS_Admin::get_instance();
} );
