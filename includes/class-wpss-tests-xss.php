<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * XSS Test Module
 *
 * Tests the target site's own forms and URL parameters for
 * reflected/DOM XSS vulnerabilities using passive and
 * semi-active probes (safe, non-destructive payloads).
 */
class WPSS_Tests_XSS {

    private $url;
    private $findings = array();

    // Safe probes that detect reflection without executing
    private $probes = array(
        '<wpssxss>'        => '/<wpssxss>/i',
        '"wpssxss"'        => '/"wpssxss"/i',
        "'>wpssxss<'"      => "/'>wpssxss</i",
        'wpssxss<script>'  => '/wpssxss<script>/i',
    );

    public function __construct( $url ) {
        $this->url = $url;
    }

    public function run() {
        $this->check_reflected_xss_in_search();
        $this->check_dom_xss_indicators();
        $this->check_wp_login_form();
        return $this->findings;
    }

    private function check_reflected_xss_in_search() {
        // Test WordPress search (?s=) endpoint
        foreach ( $this->probes as $payload => $pattern ) {
            $test_url = add_query_arg( 's', urlencode( $payload ), $this->url );
            $response = wp_remote_get( $test_url, array( 'sslverify' => false, 'timeout' => 10 ) );

            if ( is_wp_error( $response ) ) continue;

            $body = wp_remote_retrieve_body( $response );

            if ( preg_match( $pattern, $body ) ) {
                // Check if it's truly unescaped
                if ( strpos( $body, htmlspecialchars( $payload ) ) === false ) {
                    $this->add( 'high', 'Reflected XSS in Search Parameter',
                        "The search parameter (?s=) reflects user input without proper escaping. A crafted URL could execute arbitrary JavaScript in a victim's browser.",
                        "URL: {$test_url}\nPayload reflected unescaped: {$payload}",
                        "Escape all output with esc_html() or htmlspecialchars(). Use wp_kses() for HTML content. Implement a strong Content-Security-Policy."
                    );
                    return; // One finding is enough
                }
            }
        }

        $this->add( 'info', 'Search Parameter XSS — No Reflection Detected',
            'The search (?s=) parameter appears to properly encode/escape output.',
            '', ''
        );
    }

    private function check_dom_xss_indicators() {
        $response = wp_remote_get( $this->url, array( 'sslverify' => false, 'timeout' => 10 ) );
        if ( is_wp_error( $response ) ) return;

        $body = wp_remote_retrieve_body( $response );

        // Look for dangerous JS patterns that use location.hash / document.write
        $dangerous_patterns = array(
            'document.write('                              => 'document.write()',
            'innerHTML'                                    => '.innerHTML assignment',
            'location.hash'                               => 'location.hash usage',
            'eval('                                       => 'eval() usage',
            'setTimeout(document'                         => 'setTimeout with DOM manipulation',
        );

        $found = array();
        foreach ( $dangerous_patterns as $needle => $label ) {
            if ( stripos( $body, $needle ) !== false ) {
                $found[] = $label;
            }
        }

        if ( ! empty( $found ) ) {
            $this->add( 'medium', 'Potential DOM XSS Sinks Detected',
                'The page source contains JavaScript patterns commonly associated with DOM-based XSS vulnerabilities: ' . implode( ', ', $found ),
                implode( "\n", $found ),
                'Audit JavaScript code using these patterns. Replace document.write() and innerHTML with safe alternatives (textContent, createElement). Avoid passing user-controlled data to eval() or setTimeout().'
            );
        } else {
            $this->add( 'info', 'No Obvious DOM XSS Sinks Found', 'Common DOM XSS patterns not detected in page source.', '', '' );
        }
    }

    private function check_wp_login_form() {
        $login_url = wp_login_url();
        $response  = wp_remote_get( $login_url, array( 'sslverify' => false, 'timeout' => 10 ) );
        if ( is_wp_error( $response ) ) return;

        $body = wp_remote_retrieve_body( $response );

        // Check redirect_to parameter reflection
        $test_url = add_query_arg( 'redirect_to', urlencode( '<wpsstest>' ), $login_url );
        $resp2    = wp_remote_get( $test_url, array( 'sslverify' => false, 'timeout' => 10 ) );
        if ( is_wp_error( $resp2 ) ) return;

        $body2 = wp_remote_retrieve_body( $resp2 );

        if ( stripos( $body2, '<wpsstest>' ) !== false && strpos( $body2, '&lt;wpsstest&gt;' ) === false ) {
            $this->add( 'high', 'Potential XSS in Login redirect_to Parameter',
                'The wp-login.php redirect_to parameter may reflect user input without encoding.',
                "Unescaped <wpsstest> found in response.",
                'Ensure redirect_to is validated with wp_validate_redirect() and output is escaped.'
            );
        } else {
            $this->add( 'info', 'Login redirect_to Parameter Appears Safe', 'No unescaped reflection detected in redirect_to.', '', '' );
        }
    }

    private function add( $severity, $title, $description, $evidence, $remediation ) {
        $this->findings[] = compact( 'severity', 'title', 'description', 'evidence', 'remediation' )
            + array( 'test_type' => 'xss', 'ai_analysis' => '' );
    }
}
