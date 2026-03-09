<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSS_Tests_Headers {

    private $url;
    private $findings = array();

    public function __construct( $url ) {
        $this->url = $url;
    }

    public function run() {
        $response = wp_remote_get( $this->url, array( 'sslverify' => false, 'timeout' => 15 ) );
        if ( is_wp_error( $response ) ) {
            $this->add( 'high', 'Headers Check Failed', 'Unable to fetch target URL: ' . $response->get_error_message(), '', '' );
            return $this->findings;
        }

        $this->check_csp( $response );
        $this->check_x_frame( $response );
        $this->check_xss_protection( $response );
        $this->check_content_type( $response );
        $this->check_referrer_policy( $response );
        $this->check_permissions_policy( $response );
        $this->check_server_header( $response );
        $this->check_x_powered_by( $response );

        return $this->findings;
    }

    private function check_csp( $response ) {
        $header = wp_remote_retrieve_header( $response, 'content-security-policy' );
        if ( empty( $header ) ) {
            $this->add( 'high', 'Missing Content-Security-Policy Header',
                'No CSP header found. Attackers can inject malicious scripts (XSS) without browser-level mitigation.',
                'content-security-policy: (not present)',
                "Add a CSP header. Minimum: Content-Security-Policy: default-src 'self'"
            );
        } else {
            // Check for unsafe directives
            $unsafe = array();
            if ( strpos( $header, "'unsafe-inline'" ) !== false ) $unsafe[] = "'unsafe-inline'";
            if ( strpos( $header, "'unsafe-eval'" )   !== false ) $unsafe[] = "'unsafe-eval'";

            if ( ! empty( $unsafe ) ) {
                $this->add( 'medium', 'Weak CSP — Unsafe Directives Found',
                    'CSP contains unsafe directives: ' . implode( ', ', $unsafe ) . '. These weaken XSS protection.',
                    $header,
                    "Remove 'unsafe-inline' and 'unsafe-eval' from CSP. Use nonces or hashes instead."
                );
            } else {
                $this->add( 'info', 'CSP Header Present', 'Content-Security-Policy header is set.', $header, '' );
            }
        }
    }

    private function check_x_frame( $response ) {
        $header = wp_remote_retrieve_header( $response, 'x-frame-options' );
        $csp    = wp_remote_retrieve_header( $response, 'content-security-policy' );

        if ( empty( $header ) && strpos( $csp, 'frame-ancestors' ) === false ) {
            $this->add( 'medium', 'Missing X-Frame-Options Header',
                'No X-Frame-Options or CSP frame-ancestors directive. Site may be vulnerable to clickjacking attacks.',
                'x-frame-options: (not present)',
                'Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN'
            );
        } else {
            $this->add( 'info', 'Clickjacking Protection Present', 'X-Frame-Options or CSP frame-ancestors is set.', $header, '' );
        }
    }

    private function check_xss_protection( $response ) {
        $header = wp_remote_retrieve_header( $response, 'x-xss-protection' );
        if ( empty( $header ) ) {
            $this->add( 'low', 'Missing X-XSS-Protection Header',
                'X-XSS-Protection header is absent. While modern browsers rely on CSP, legacy browsers have no extra protection.',
                'x-xss-protection: (not present)',
                "Add: X-XSS-Protection: 1; mode=block"
            );
        } elseif ( $header === '0' ) {
            $this->add( 'medium', 'X-XSS-Protection Disabled',
                'X-XSS-Protection is explicitly set to 0, disabling the browser\'s built-in XSS filter.',
                "x-xss-protection: {$header}",
                "Change to: X-XSS-Protection: 1; mode=block"
            );
        } else {
            $this->add( 'info', 'X-XSS-Protection Present', "Header value: {$header}", $header, '' );
        }
    }

    private function check_content_type( $response ) {
        $header = wp_remote_retrieve_header( $response, 'x-content-type-options' );
        if ( strtolower( trim( $header ) ) !== 'nosniff' ) {
            $this->add( 'medium', 'Missing X-Content-Type-Options: nosniff',
                'Without nosniff, browsers may MIME-sniff responses and execute malicious files as scripts.',
                "x-content-type-options: " . ( $header ?: '(not present)' ),
                'Add: X-Content-Type-Options: nosniff'
            );
        } else {
            $this->add( 'info', 'X-Content-Type-Options Set', 'nosniff is configured.', $header, '' );
        }
    }

    private function check_referrer_policy( $response ) {
        $header = wp_remote_retrieve_header( $response, 'referrer-policy' );
        if ( empty( $header ) ) {
            $this->add( 'low', 'Missing Referrer-Policy Header',
                'No Referrer-Policy set. Sensitive URL parameters may leak to third-party sites via the Referer header.',
                'referrer-policy: (not present)',
                'Add: Referrer-Policy: strict-origin-when-cross-origin'
            );
        } else {
            $this->add( 'info', 'Referrer-Policy Set', "Value: {$header}", $header, '' );
        }
    }

    private function check_permissions_policy( $response ) {
        $header = wp_remote_retrieve_header( $response, 'permissions-policy' );
        if ( empty( $header ) ) {
            $this->add( 'low', 'Missing Permissions-Policy Header',
                'No Permissions-Policy header. Browser features like camera, microphone, geolocation are unrestricted.',
                'permissions-policy: (not present)',
                'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()'
            );
        } else {
            $this->add( 'info', 'Permissions-Policy Set', "Value: {$header}", $header, '' );
        }
    }

    private function check_server_header( $response ) {
        $header = wp_remote_retrieve_header( $response, 'server' );
        if ( ! empty( $header ) && preg_match( '/\d+\.\d+/', $header ) ) {
            $this->add( 'medium', 'Server Header Discloses Version Information',
                "The Server header reveals software version: {$header}. Attackers can use this to find known CVEs.",
                "server: {$header}",
                'Configure your web server to suppress or genericise the Server header.'
            );
        }
    }

    private function check_x_powered_by( $response ) {
        $header = wp_remote_retrieve_header( $response, 'x-powered-by' );
        if ( ! empty( $header ) ) {
            $this->add( 'medium', 'X-Powered-By Header Exposes Technology Stack',
                "X-Powered-By: {$header} reveals backend technology, aiding targeted attacks.",
                "x-powered-by: {$header}",
                'Remove X-Powered-By header in your server/PHP configuration.'
            );
        }
    }

    private function add( $severity, $title, $description, $evidence, $remediation ) {
        $this->findings[] = compact( 'severity', 'title', 'description', 'evidence', 'remediation' )
            + array( 'test_type' => 'headers', 'ai_analysis' => '' );
    }
}
