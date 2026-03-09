<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSS_Tests_SSL {

    private $url;
    private $host;
    private $findings = array();

    public function __construct( $url ) {
        $this->url  = $url;
        $this->host = wp_parse_url( $url, PHP_URL_HOST );
    }

    public function run() {
        $this->check_https_enforced();
        $this->check_certificate();
        $this->check_hsts();
        $this->check_http_redirect();
        return $this->findings;
    }

    private function check_https_enforced() {
        if ( strpos( $this->url, 'https://' ) !== 0 ) {
            $this->add( 'high', 'Site Not Using HTTPS',
                'The target URL does not use HTTPS. All data transmitted is unencrypted and vulnerable to interception.',
                'URL scheme is HTTP',
                'Enable HTTPS by installing a TLS certificate (e.g. Let\'s Encrypt) and redirect all HTTP traffic to HTTPS.'
            );
        } else {
            $this->add( 'info', 'HTTPS Enabled', 'Site is using HTTPS.', '', '' );
        }
    }

    private function check_certificate() {
        if ( strpos( $this->url, 'https://' ) !== 0 ) return;

        $context = stream_context_create( array(
            'ssl' => array(
                'capture_peer_cert' => true,
                'verify_peer'       => true,
                'verify_peer_name'  => true,
            )
        ) );

        $stream = @stream_socket_client(
            "ssl://{$this->host}:443",
            $errno, $errstr, 10,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ( ! $stream ) {
            $this->add( 'critical', 'SSL Certificate Invalid or Untrusted',
                "Unable to establish SSL connection: {$errstr} (#{$errno})",
                $errstr,
                'Ensure a valid, trusted TLS certificate is installed. Check certificate chain and expiry.'
            );
            return;
        }

        $params = stream_context_get_params( $stream );
        $cert   = openssl_x509_parse( $params['options']['ssl']['peer_certificate'] );
        fclose( $stream );

        if ( $cert ) {
            $expiry = $cert['validTo_time_t'];
            $days   = round( ( $expiry - time() ) / 86400 );

            if ( $days < 0 ) {
                $this->add( 'critical', 'SSL Certificate Expired',
                    "The SSL certificate expired " . abs( $days ) . " days ago.",
                    "CN={$cert['subject']['CN']}, expired=" . date( 'Y-m-d', $expiry ),
                    'Renew the SSL certificate immediately.'
                );
            } elseif ( $days < 30 ) {
                $this->add( 'medium', 'SSL Certificate Expiring Soon',
                    "The SSL certificate expires in {$days} days.",
                    "CN={$cert['subject']['CN']}, expires=" . date( 'Y-m-d', $expiry ),
                    'Renew the SSL certificate before it expires to avoid service disruption.'
                );
            } else {
                $this->add( 'info', 'SSL Certificate Valid',
                    "Certificate valid for {$days} more days.",
                    "CN={$cert['subject']['CN']}", ''
                );
            }
        }
    }

    private function check_hsts() {
        $response = wp_remote_get( $this->url, array( 'sslverify' => false, 'timeout' => 10 ) );
        if ( is_wp_error( $response ) ) return;

        $hsts = wp_remote_retrieve_header( $response, 'strict-transport-security' );
        if ( empty( $hsts ) ) {
            $this->add( 'medium', 'Missing HSTS Header',
                'HTTP Strict Transport Security (HSTS) header is not set. Browsers may allow downgrade attacks.',
                'Header: strict-transport-security = (not present)',
                'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
            );
        } else {
            $this->add( 'info', 'HSTS Header Present', "HSTS header found: {$hsts}", $hsts, '' );
        }
    }

    private function check_http_redirect() {
        $http_url = str_replace( 'https://', 'http://', $this->url );
        $response = wp_remote_get( $http_url, array(
            'redirection' => 0,
            'timeout'     => 10,
            'sslverify'   => false,
        ) );

        if ( is_wp_error( $response ) ) return;

        $code     = wp_remote_retrieve_response_code( $response );
        $location = wp_remote_retrieve_header( $response, 'location' );

        if ( in_array( $code, array( 301, 302, 307, 308 ) ) && strpos( $location, 'https://' ) === 0 ) {
            $this->add( 'info', 'HTTP Redirects to HTTPS', "HTTP traffic is redirected (HTTP {$code}) to HTTPS.", "Location: {$location}", '' );
        } else {
            $this->add( 'high', 'HTTP Not Redirected to HTTPS',
                'HTTP requests are not redirected to HTTPS. Users may access the site over insecure HTTP.',
                "HTTP {$code}, Location: {$location}",
                'Add a 301 redirect from HTTP to HTTPS in your .htaccess or server config.'
            );
        }
    }

    private function add( $severity, $title, $description, $evidence, $remediation ) {
        $this->findings[] = compact( 'severity', 'title', 'description', 'evidence', 'remediation' )
            + array( 'test_type' => 'ssl', 'ai_analysis' => '' );
    }
}
