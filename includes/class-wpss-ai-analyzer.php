<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * AI Analyzer — multi-provider support.
 * Providers: anthropic, openai, gemini, mistral
 */
class WPSS_AI_Analyzer {

    private $provider;
    private $api_key;
    private $model;

    private static $providers = array(
        'anthropic' => array(
            'label'         => 'Anthropic (Claude)',
            'key_label'     => 'API Key from console.anthropic.com',
            'models'        => array(
                'claude-opus-4-5'            => 'Claude Opus 4.5',
                'claude-sonnet-4-5'          => 'Claude Sonnet 4.5',
                'claude-haiku-4-5-20251001'  => 'Claude Haiku 4.5',
            ),
            'default_model' => 'claude-opus-4-5',
        ),
        'openai' => array(
            'label'         => 'OpenAI (GPT)',
            'key_label'     => 'API Key from platform.openai.com',
            'models'        => array(
                'gpt-4o'      => 'GPT-4o',
                'gpt-4o-mini' => 'GPT-4o Mini',
                'gpt-4-turbo' => 'GPT-4 Turbo',
            ),
            'default_model' => 'gpt-4o',
        ),
        'gemini' => array(
            'label'         => 'Google Gemini',
            'key_label'     => 'API Key from aistudio.google.com',
            'models'        => array(
                'gemini-2.5-flash-lite-preview-06-17' => 'Gemini 2.5 Flash Lite',
                'gemini-2.5-flash-preview-05-20'      => 'Gemini 2.5 Flash',
                'gemini-2.5-pro-preview-06-05'        => 'Gemini 2.5 Pro',
            ),
            'default_model' => 'gemini-2.5-flash-lite-preview-06-17',
        ),
        'mistral' => array(
            'label'         => 'Mistral AI',
            'key_label'     => 'API Key from console.mistral.ai',
            'models'        => array(
                'mistral-large-latest' => 'Mistral Large',
                'mistral-small-latest' => 'Mistral Small',
                'open-mixtral-8x22b'   => 'Mixtral 8x22B',
            ),
            'default_model' => 'mistral-large-latest',
        ),
    );

    public function __construct() {
        $this->provider = get_option( 'wpss_ai_provider', 'none' );
        $this->api_key  = get_option( 'wpss_ai_api_key_' . $this->provider, '' );
        $this->model    = get_option( 'wpss_ai_model_' . $this->provider,
                          self::$providers[ $this->provider ]['default_model'] ?? '' );
    }

    public static function get_providers() {
        return self::$providers;
    }

    public function is_configured() {
        return $this->provider !== 'none' && ! empty( $this->api_key );
    }

    public function summarize( $findings ) {
        if ( ! $this->is_configured() || empty( $findings ) ) return '';

        $counts = array_count_values( array_column( $findings, 'severity' ) );
        $list   = '';
        foreach ( $findings as $f ) {
            if ( in_array( $f['severity'], array( 'critical', 'high', 'medium' ) ) ) {
                $list .= "- [{$f['severity']}] {$f['title']}: {$f['description']}\n";
            }
        }
        if ( empty( $list ) ) $list = 'No critical/high/medium findings.';

        $prompt = "You are a senior penetration tester writing an executive summary for a WordPress security scan report.\n\n"
            . "Scan statistics:\n"
            . "- Critical: " . ( $counts['critical'] ?? 0 ) . "\n"
            . "- High: "     . ( $counts['high']     ?? 0 ) . "\n"
            . "- Medium: "   . ( $counts['medium']   ?? 0 ) . "\n"
            . "- Low: "      . ( $counts['low']      ?? 0 ) . "\n"
            . "- Info: "     . ( $counts['info']     ?? 0 ) . "\n\n"
            . "Key findings:\n{$list}\n\n"
            . "Write a concise 3-4 paragraph executive summary: overall risk posture, most critical issues, business impact, and top 3 immediate actions. Use plain technical language.";

        return $this->call( $prompt );
    }

    public function analyze_finding( $finding ) {
        if ( ! $this->is_configured() ) return '';

        $prompt = "You are a senior penetration tester. Analyze this WordPress security vulnerability and provide actionable developer advice.\n\n"
            . "Vulnerability: {$finding['title']}\n"
            . "Severity: {$finding['severity']}\n"
            . "Test Type: {$finding['test_type']}\n"
            . "Description: {$finding['description']}\n"
            . "Evidence: {$finding['evidence']}\n"
            . "Basic Remediation: {$finding['remediation']}\n\n"
            . "Provide:\n"
            . "1. Root Cause: Why this exists (2-3 sentences)\n"
            . "2. Attack Scenario: Realistic exploitation scenario (2-3 sentences)\n"
            . "3. Detailed Fix: Step-by-step WordPress-specific code or config\n"
            . "4. Verification: How to confirm the fix was successful\n\n"
            . "Be technical and concise. Include specific PHP/WordPress code snippets.";

        return $this->call( $prompt );
    }

    private function call( $prompt ) {
        switch ( $this->provider ) {
            case 'openai':  return $this->call_openai( $prompt );
            case 'gemini':  return $this->call_gemini( $prompt );
            case 'mistral': return $this->call_mistral( $prompt );
            default:        return $this->call_anthropic( $prompt );
        }
    }

    private function call_anthropic( $prompt ) {
        $response = wp_remote_post( 'https://api.anthropic.com/v1/messages', array(
            'timeout' => 60,
            'headers' => array(
                'x-api-key'         => $this->api_key,
                'anthropic-version' => '2023-06-01',
                'content-type'      => 'application/json',
            ),
            'body' => wp_json_encode( array(
                'model'      => $this->model,
                'max_tokens' => 1024,
                'messages'   => array( array( 'role' => 'user', 'content' => $prompt ) ),
            ) ),
        ) );
        if ( is_wp_error( $response ) ) return 'AI unavailable: ' . $response->get_error_message();
        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( wp_remote_retrieve_response_code( $response ) !== 200 )
            return 'AI error: ' . ( $body['error']['message'] ?? 'Unknown' );
        return $body['content'][0]['text'] ?? '';
    }

    private function call_openai( $prompt ) {
        $response = wp_remote_post( 'https://api.openai.com/v1/chat/completions', array(
            'timeout' => 60,
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type'  => 'application/json',
            ),
            'body' => wp_json_encode( array(
                'model'      => $this->model,
                'max_tokens' => 1024,
                'messages'   => array( array( 'role' => 'user', 'content' => $prompt ) ),
            ) ),
        ) );
        if ( is_wp_error( $response ) ) return 'AI unavailable: ' . $response->get_error_message();
        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( wp_remote_retrieve_response_code( $response ) !== 200 )
            return 'AI error: ' . ( $body['error']['message'] ?? 'Unknown' );
        return $body['choices'][0]['message']['content'] ?? '';
    }

    private function call_gemini( $prompt ) {
        $url = "https://generativelanguage.googleapis.com/v1beta/models/{$this->model}:generateContent?key={$this->api_key}";
        $response = wp_remote_post( $url, array(
            'timeout' => 60,
            'headers' => array( 'Content-Type' => 'application/json' ),
            'body'    => wp_json_encode( array(
                'contents' => array( array( 'parts' => array( array( 'text' => $prompt ) ) ) ),
            ) ),
        ) );
        if ( is_wp_error( $response ) ) return 'AI unavailable: ' . $response->get_error_message();
        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( wp_remote_retrieve_response_code( $response ) !== 200 )
            return 'AI error: ' . ( $body['error']['message'] ?? 'Unknown' );
        return $body['candidates'][0]['content']['parts'][0]['text'] ?? '';
    }

    private function call_mistral( $prompt ) {
        $response = wp_remote_post( 'https://api.mistral.ai/v1/chat/completions', array(
            'timeout' => 60,
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type'  => 'application/json',
            ),
            'body' => wp_json_encode( array(
                'model'      => $this->model,
                'max_tokens' => 1024,
                'messages'   => array( array( 'role' => 'user', 'content' => $prompt ) ),
            ) ),
        ) );
        if ( is_wp_error( $response ) ) return 'AI unavailable: ' . $response->get_error_message();
        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( wp_remote_retrieve_response_code( $response ) !== 200 )
            return 'AI error: ' . ( $body['error']['message'] ?? 'Unknown' );
        return $body['choices'][0]['message']['content'] ?? '';
    }
}
