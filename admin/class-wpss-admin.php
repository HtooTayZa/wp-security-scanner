<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSS_Admin {

    private static $instance = null;

    public static function get_instance() {
        if ( null === self::$instance ) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        add_action( 'admin_menu',            array( $this, 'add_menu' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
        add_action( 'wp_ajax_wpss_run_scan',   array( $this, 'ajax_run_scan' ) );
        add_action( 'wp_ajax_wpss_get_report', array( $this, 'ajax_get_report' ) );
        add_action( 'admin_init',            array( $this, 'register_settings' ) );
    }

    public function add_menu() {
        add_menu_page( 'Security Scanner', 'Security Scanner', 'manage_options',
            'wp-security-scanner', array( $this, 'render_dashboard' ), 'dashicons-shield', 80 );
        add_submenu_page( 'wp-security-scanner', 'Settings', 'Settings', 'manage_options',
            'wp-security-scanner-settings', array( $this, 'render_settings' ) );
    }

    public function enqueue_assets( $hook ) {
        if ( strpos( $hook, 'wp-security-scanner' ) === false ) return;
        wp_enqueue_style(  'wpss-admin', WPSS_PLUGIN_URL . 'assets/css/admin.css', array(), WPSS_VERSION );
        wp_enqueue_script( 'wpss-admin', WPSS_PLUGIN_URL . 'assets/js/admin.js',  array( 'jquery' ), WPSS_VERSION, true );
        wp_localize_script( 'wpss-admin', 'WPSS', array(
            'ajax_url' => admin_url( 'admin-ajax.php' ),
            'nonce'    => wp_create_nonce( 'wpss_nonce' ),
            'site_url' => get_site_url(),
        ) );
    }

    public function register_settings() {
        $fields = array( 'wpss_ai_provider' );
        foreach ( WPSS_AI_Analyzer::get_providers() as $key => $p ) {
            $fields[] = 'wpss_ai_api_key_' . $key;
            $fields[] = 'wpss_ai_model_'   . $key;
        }
        foreach ( $fields as $f ) {
            register_setting( 'wpss_settings_group', $f, array( 'sanitize_callback' => 'sanitize_text_field' ) );
        }
    }

    public function ajax_run_scan() {
        check_ajax_referer( 'wpss_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Unauthorized', 403 );

        $url   = isset( $_POST['url'] )   ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : get_site_url();
        $tests = isset( $_POST['tests'] ) ? array_map( 'sanitize_key', (array) $_POST['tests'] ) : array();

        if ( empty( $url ) ) wp_send_json_error( 'Invalid URL' );
        set_time_limit( 300 );

        $scanner = new WPSS_Scanner( $url );
        $result  = $scanner->run( $tests );
        wp_send_json_success( $result );
    }

    public function ajax_get_report() {
        check_ajax_referer( 'wpss_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Unauthorized', 403 );
        $scan_id = intval( $_POST['scan_id'] ?? 0 );
        if ( ! $scan_id ) wp_send_json_error( 'Invalid scan ID' );
        wp_send_json_success( array( 'html' => WPSS_Report::generate_html( $scan_id ) ) );
    }

    public function render_settings() {
        $providers       = WPSS_AI_Analyzer::get_providers();
        $active_provider = get_option( 'wpss_ai_provider', 'none' );
        ?>
        <div class="wpss-wrap">
          <div class="wpss-page-title">Settings</div>
          <form method="post" action="options.php">
            <?php settings_fields( 'wpss_settings_group' ); ?>

            <div class="wpss-settings-section">
              <div class="wpss-settings-label">AI Analysis
                <span class="wpss-field-hint">Optional — scans work fully without AI. Configure a provider to add root cause analysis and fix recommendations to findings.</span>
              </div>
              <div class="wpss-provider-grid">
                <label class="wpss-provider-card <?php echo $active_provider === 'none' ? 'is-active' : ''; ?>">
                  <input type="radio" name="wpss_ai_provider" value="none"
                    <?php checked( $active_provider, 'none' ); ?> class="wpss-provider-radio" />
                  <span class="wpss-provider-name">None / Disabled</span>
                </label>
                <?php foreach ( $providers as $key => $p ) : ?>
                <label class="wpss-provider-card <?php echo $active_provider === $key ? 'is-active' : ''; ?>">
                  <input type="radio" name="wpss_ai_provider" value="<?php echo esc_attr( $key ); ?>"
                    <?php checked( $active_provider, $key ); ?> class="wpss-provider-radio" />
                  <span class="wpss-provider-name"><?php echo esc_html( $p['label'] ); ?></span>
                </label>
                <?php endforeach; ?>
              </div>
            </div>

            <div class="wpss-settings-section wpss-provider-fields" data-provider="none"
                 style="<?php echo $active_provider !== 'none' ? 'display:none;' : ''; ?>">
              <div class="wpss-settings-label">AI Disabled</div>
              <p class="wpss-none-note">
                The scanner will run all selected security modules and report findings without AI analysis.
                All vulnerability data, risk scoring, and remediation guidance is built-in and works independently.
                Select a provider above whenever you want to enable AI-powered analysis.
              </p>
            </div>

            <?php foreach ( $providers as $key => $p ) :
              $saved_key   = get_option( 'wpss_ai_api_key_' . $key, '' );
              $saved_model = get_option( 'wpss_ai_model_'   . $key, $p['default_model'] );
            ?>
            <div class="wpss-settings-section wpss-provider-fields" data-provider="<?php echo esc_attr( $key ); ?>"
                 style="<?php echo $active_provider !== $key ? 'display:none;' : ''; ?>">
              <div class="wpss-settings-label"><?php echo esc_html( $p['label'] ); ?> — Configuration</div>
              <div class="wpss-field-row">
                <label class="wpss-field-label">
                  API Key
                  <span class="wpss-field-hint"><?php echo esc_html( $p['key_label'] ); ?></span>
                </label>
                <input type="password" name="wpss_ai_api_key_<?php echo esc_attr( $key ); ?>"
                       value="<?php echo esc_attr( $saved_key ); ?>"
                       class="wpss-input" placeholder="Paste your API key here" />
              </div>
              <div class="wpss-field-row">
                <label class="wpss-field-label">Model</label>
                <select name="wpss_ai_model_<?php echo esc_attr( $key ); ?>" class="wpss-select">
                  <?php foreach ( $p['models'] as $mkey => $mlabel ) : ?>
                  <option value="<?php echo esc_attr( $mkey ); ?>" <?php selected( $saved_model, $mkey ); ?>>
                    <?php echo esc_html( $mlabel ); ?>
                  </option>
                  <?php endforeach; ?>
                </select>
              </div>
            </div>
            <?php endforeach; ?>

            <div class="wpss-settings-footer">
              <?php submit_button( 'Save Settings', 'primary', 'submit', false ); ?>
            </div>
          </form>
        </div>

        <script>
        (function() {
          function switchProvider(value) {
            // Update card active state
            document.querySelectorAll('.wpss-provider-card').forEach(function(card) {
              var radio = card.querySelector('.wpss-provider-radio');
              card.classList.toggle('is-active', radio && radio.value === value);
            });
            // Show/hide config panels
            document.querySelectorAll('.wpss-provider-fields').forEach(function(panel) {
              panel.style.display = panel.dataset.provider === value ? '' : 'none';
            });
          }

          // Bind radio change events
          document.querySelectorAll('.wpss-provider-radio').forEach(function(radio) {
            radio.addEventListener('change', function() {
              switchProvider(this.value);
            });
          });

          // Also handle clicks on the label/card itself
          document.querySelectorAll('.wpss-provider-card').forEach(function(card) {
            card.addEventListener('click', function() {
              var radio = this.querySelector('.wpss-provider-radio');
              if (radio) switchProvider(radio.value);
            });
          });
        })();
        </script>
        <?php
    }

    public function render_dashboard() {
        $recent_scans   = WPSS_Database::get_recent_scans( 5 );
        $ai             = new WPSS_AI_Analyzer();
        $ai_configured  = $ai->is_configured();
        $ai_provider    = get_option( 'wpss_ai_provider', 'none' );
        $providers      = WPSS_AI_Analyzer::get_providers();
        $provider_label = isset( $providers[ $ai_provider ] ) ? $providers[ $ai_provider ]['label'] : 'Disabled';
        ?>
        <div class="wpss-wrap">

          <div class="wpss-top-bar">
            <div class="wpss-top-bar-left">
              <span class="wpss-wordmark">Security Scanner</span>
              <span class="wpss-version">v<?php echo WPSS_VERSION; ?></span>
            </div>
            <div class="wpss-top-bar-right">
              <?php if ( $ai_configured ) : ?>
                <span class="wpss-ai-badge is-on">AI &middot; <?php echo esc_html( $provider_label ); ?></span>
              <?php else : ?>
                <a href="<?php echo admin_url( 'admin.php?page=wp-security-scanner-settings' ); ?>" class="wpss-ai-badge is-off">AI disabled &mdash; configure</a>
              <?php endif; ?>
              <a href="<?php echo admin_url( 'admin.php?page=wp-security-scanner-settings' ); ?>" class="wpss-link">Settings</a>
            </div>
          </div>

          <!-- Scan panel -->
          <div class="wpss-panel">
            <div class="wpss-panel-header">
              <div class="wpss-panel-title">New Scan</div>
              <div class="wpss-panel-sub">Run a vulnerability assessment against your WordPress installation.</div>
            </div>

            <?php if ( ! $ai_configured ) : ?>
            <div class="wpss-notice-optional">
              AI analysis is optional. Configure a provider in
              <a href="<?php echo admin_url( 'admin.php?page=wp-security-scanner-settings' ); ?>">Settings</a>
              to get root cause explanations and fix recommendations alongside scan results.
            </div>
            <?php endif; ?>

            <div class="wpss-field-row">
              <label class="wpss-field-label">Target URL</label>
              <input type="url" id="wpss-target-url" class="wpss-input"
                     value="<?php echo esc_attr( get_site_url() ); ?>" />
            </div>

            <div class="wpss-field-row">
              <label class="wpss-field-label">Modules</label>
              <div class="wpss-module-grid">
                <?php
                $modules = array(
                    'ssl'     => 'SSL / TLS',
                    'headers' => 'Security Headers',
                    'xss'     => 'XSS Detection',
                    'sqli'    => 'SQL Injection',
                    'pentest' => 'Pen Test / Recon',
                );
                foreach ( $modules as $key => $label ) : ?>
                <label class="wpss-module-item">
                  <input type="checkbox" class="wpss-module-check" value="<?php echo esc_attr( $key ); ?>" checked />
                  <span class="wpss-module-box"></span>
                  <span class="wpss-module-label"><?php echo esc_html( $label ); ?></span>
                </label>
                <?php endforeach; ?>
              </div>
            </div>

            <button id="wpss-run-btn" class="wpss-btn-primary">Run Scan</button>
          </div>

          <!-- Progress -->
          <div class="wpss-panel wpss-progress-panel" id="wpss-progress" style="display:none;">
            <div class="wpss-progress-top">
              <div class="wpss-progress-dot"></div>
              <span id="wpss-progress-text" class="wpss-progress-msg">Initializing</span>
              <span id="wpss-progress-pct" class="wpss-progress-pct">0%</span>
            </div>
            <div class="wpss-progress-track"><div class="wpss-progress-fill" id="wpss-progress-bar"></div></div>
          </div>

          <!-- Results injected here -->
          <div id="wpss-results-container"></div>

          <!-- Recent scans -->
          <?php if ( ! empty( $recent_scans ) ) : ?>
          <div class="wpss-panel">
            <div class="wpss-panel-header">
              <div class="wpss-panel-title">Recent Scans</div>
            </div>
            <table class="wpss-table">
              <thead>
                <tr>
                  <th>ID</th><th>Target</th><th>Risk</th><th>Status</th><th>Date</th><th></th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ( $recent_scans as $scan ) :
                  $rc = $scan->risk_score >= 70 ? 'high' : ( $scan->risk_score >= 40 ? 'medium' : 'low' );
                ?>
                <tr>
                  <td class="wpss-mono">#<?php echo intval( $scan->id ); ?></td>
                  <td class="wpss-mono wpss-url-cell"><?php echo esc_html( $scan->target_url ); ?></td>
                  <td><span class="wpss-risk-chip risk-<?php echo $rc; ?>"><?php echo intval( $scan->risk_score ); ?></span></td>
                  <td><span class="wpss-status-chip status-<?php echo esc_attr( $scan->status ); ?>"><?php echo esc_html( ucfirst( $scan->status ) ); ?></span></td>
                  <td class="wpss-muted"><?php echo esc_html( date( 'M j, Y H:i', strtotime( $scan->created_at ) ) ); ?></td>
                  <td><button class="wpss-btn-ghost wpss-view-report" data-scan-id="<?php echo intval( $scan->id ); ?>">Report</button></td>
                </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
          <?php endif; ?>

        </div><!-- .wpss-wrap -->

        <!-- Report modal -->
        <div id="wpss-report-modal" class="wpss-modal" style="display:none;">
          <div class="wpss-modal-backdrop" id="wpss-modal-backdrop"></div>
          <div class="wpss-modal-window">
            <div class="wpss-modal-bar">
              <span class="wpss-modal-bar-title">Security Report</span>
              <div class="wpss-modal-bar-actions">
                <button id="wpss-print-btn" class="wpss-btn-ghost">Print / PDF</button>
                <button id="wpss-close-modal" class="wpss-btn-ghost">Close</button>
              </div>
            </div>
            <iframe id="wpss-report-frame" src="about:blank"></iframe>
          </div>
        </div>


        <?php
    }
}
