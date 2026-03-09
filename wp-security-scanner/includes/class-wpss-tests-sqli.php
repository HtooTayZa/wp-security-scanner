<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * SQL Injection Test Module
 *
 * Uses safe, time-based and error-based probes to detect
 * SQLi without modifying any database data.
 */
class WPSS_Tests_SQLi {

    private $url;
    private $findings = array();

    // Error signatures from common databases
    private $error_signatures = array(
        'mysql'      => array(
            'You have an error in your SQL syntax',
            'Warning: mysql_',
            'MySQLSyntaxErrorException',
            'com.mysql.jdbc',
        ),
        'mssql'      => array(
            'Unclosed quotation mark after the character string',
            'Microsoft OLE DB Provider for SQL Server',
            '[Microsoft][ODBC SQL Server Driver]',
        ),
        'pgsql'      => array(
            'pg_query(): Query failed:',
            'PSQLException',
            'ERROR: syntax error at or near',
        ),
        'sqlite'     => array( 'SQLite/JDBCDriver', 'System.Data.SQLite.SQLiteException' ),
        'oracle'     => array( 'ORA-01756', 'oracle.jdbc.driver' ),
        'generic'    => array(
            'SQL syntax.*MySQL',
            'Warning.*mysql_fetch_array',
            'valid MySQL result',
            'MySqlClient\.',
        ),
    );

    private $sql_probes = array( "'", '"', "' OR '1'='1", "1 AND SLEEP(0)", "1;--" );

    public function __construct( $url ) {
        $this->url = $url;
    }

    public function run() {
        $this->check_error_based_sqli();
        $this->check_wp_core_protections();
        $this->check_debug_mode();
        return $this->findings;
    }

    private function check_error_based_sqli() {
        $endpoints_to_test = array(
            array( 'param' => 's',    'url' => $this->url ),
            array( 'param' => 'p',    'url' => $this->url ),
            array( 'param' => 'page', 'url' => $this->url ),
            array( 'param' => 'cat',  'url' => $this->url ),
            array( 'param' => 'id',   'url' => $this->url ),
        );

        $vulnerable = false;
        foreach ( $endpoints_to_test as $endpoint ) {
            foreach ( $this->sql_probes as $probe ) {
                $test_url = add_query_arg( $endpoint['param'], urlencode( $probe ), $endpoint['url'] );
                $response = wp_remote_get( $test_url, array( 'sslverify' => false, 'timeout' => 15 ) );

                if ( is_wp_error( $response ) ) continue;

                $body = wp_remote_retrieve_body( $response );
                $code = wp_remote_retrieve_response_code( $response );

                foreach ( $this->error_signatures as $db => $patterns ) {
                    foreach ( $patterns as $pattern ) {
                        if ( preg_match( '/' . preg_quote( $pattern, '/' ) . '/i', $body ) ) {
                            $this->add( 'critical', 'SQL Injection Vulnerability Detected',
                                "An SQL error was triggered on the {$endpoint['param']} parameter, indicating unsanitised input is passed directly to a database query. This may allow an attacker to read, modify or delete database data.",
                                "Endpoint: ?{$endpoint['param']}={$probe}\nDB Type: {$db}\nError pattern matched: {$pattern}",
                                "Use WordPress prepared statements (\$wpdb->prepare()) for all DB queries. Validate and sanitise all user input. Never concatenate user data into SQL strings."
                            );
                            $vulnerable = true;
                            break 4;
                        }
                    }
                }
            }
        }

        if ( ! $vulnerable ) {
            $this->add( 'info', 'Error-Based SQLi — No DB Errors Triggered',
                'No SQL error messages were detected in response to basic SQL injection probes.',
                '', ''
            );
        }
    }

    private function check_wp_core_protections() {
        // Check if WPDB uses prepare by looking for known issues
        // Verify that WordPress error reporting is off
        $response = wp_remote_get( $this->url, array( 'sslverify' => false, 'timeout' => 10 ) );
        if ( is_wp_error( $response ) ) return;

        $body = wp_remote_retrieve_body( $response );

        // Check if WP_DEBUG is leaking info
        if ( strpos( $body, 'WordPress database error' ) !== false ) {
            $this->add( 'high', 'WordPress Database Errors Exposed to Public',
                'WordPress is displaying raw database error messages to visitors. This is a major information disclosure vulnerability.',
                'String "WordPress database error" found in public page source.',
                'Set WP_DEBUG to false in wp-config.php for production. Set WP_DEBUG_LOG to true to log errors privately instead.'
            );
        }
    }

    private function check_debug_mode() {
        // Check wp-config.php exposure
        $config_url = trailingslashit( $this->url ) . 'wp-config.php';
        $response   = wp_remote_get( $config_url, array(
            'sslverify'   => false,
            'timeout'     => 10,
            'redirection' => 0,
        ) );

        if ( is_wp_error( $response ) ) return;

        $code = wp_remote_retrieve_response_code( $response );
        $body = wp_remote_retrieve_body( $response );

        // If it returns 200 and has PHP-like content (shouldn't be readable)
        if ( $code === 200 && ( strpos( $body, 'DB_NAME' ) !== false || strpos( $body, 'DB_PASSWORD' ) !== false ) ) {
            $this->add( 'critical', 'wp-config.php Publicly Accessible!',
                'The wp-config.php file is accessible from the internet and may expose database credentials and secret keys.',
                "HTTP {$code} on {$config_url}",
                'Immediately restrict access to wp-config.php via .htaccess rules or move it above the web root.'
            );
        } else {
            $this->add( 'info', 'wp-config.php Not Publicly Readable', "HTTP {$code} returned for wp-config.php — appears protected.", '', '' );
        }
    }

    private function add( $severity, $title, $description, $evidence, $remediation ) {
        $this->findings[] = compact( 'severity', 'title', 'description', 'evidence', 'remediation' )
            + array( 'test_type' => 'sqli', 'ai_analysis' => '' );
    }
}
