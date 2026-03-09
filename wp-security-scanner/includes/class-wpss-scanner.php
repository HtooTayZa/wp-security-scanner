<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSS_Scanner {

    private $scan_id;
    private $target_url;
    private $results = array();

    public function __construct( $target_url ) {
        $this->target_url = trailingslashit( esc_url_raw( $target_url ) );
        $this->scan_id    = WPSS_Database::create_scan( $this->target_url );
    }

    public function get_scan_id() {
        return $this->scan_id;
    }

    /**
     * Run all enabled security tests.
     */
    public function run( $tests = array() ) {
        $available = array(
            'ssl'     => 'WPSS_Tests_SSL',
            'headers' => 'WPSS_Tests_Headers',
            'xss'     => 'WPSS_Tests_XSS',
            'sqli'    => 'WPSS_Tests_SQLi',
            'pentest' => 'WPSS_Tests_Pentest',
        );

        if ( empty( $tests ) ) {
            $tests = array_keys( $available );
        }

        foreach ( $tests as $key ) {
            if ( isset( $available[ $key ] ) ) {
                $class    = $available[ $key ];
                $instance = new $class( $this->target_url );
                $findings = $instance->run();

                foreach ( $findings as $finding ) {
                    $this->results[] = $finding;
                    WPSS_Database::save_result( $this->scan_id, $finding );
                }
            }
        }

        // AI analysis — only runs if a provider is configured
        $ai_summary  = '';
        $ai_analyzer = new WPSS_AI_Analyzer();

        if ( $ai_analyzer->is_configured() ) {
            $ai_summary = $ai_analyzer->summarize( $this->results );

            foreach ( $this->results as &$result ) {
                if ( in_array( $result['severity'], array( 'critical', 'high', 'medium' ) ) ) {
                    $result['ai_analysis'] = $ai_analyzer->analyze_finding( $result );
                }
            }
            unset( $result );
        }

        $risk_score = $this->calculate_risk_score();
        WPSS_Database::complete_scan( $this->scan_id, $risk_score, $ai_summary );

        return array(
            'scan_id'    => $this->scan_id,
            'risk_score' => $risk_score,
            'results'    => $this->results,
            'ai_summary' => $ai_summary,
        );
    }

    private function calculate_risk_score() {
        $weights = array( 'critical' => 40, 'high' => 20, 'medium' => 10, 'low' => 5, 'info' => 1 );
        $score   = 0;
        foreach ( $this->results as $r ) {
            $score += isset( $weights[ $r['severity'] ] ) ? $weights[ $r['severity'] ] : 0;
        }
        return min( 100, $score );
    }
}
