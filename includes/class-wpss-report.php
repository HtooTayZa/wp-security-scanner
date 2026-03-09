<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSS_Report {

    public static function generate_html( $scan_id ) {
        $scan    = WPSS_Database::get_scan( $scan_id );
        $results = WPSS_Database::get_results( $scan_id );
        if ( ! $scan ) return '';

        $counts = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0 );
        foreach ( $results as $r ) {
            if ( isset( $counts[ $r->severity ] ) ) $counts[ $r->severity ]++;
        }

        $score       = intval( $scan->risk_score );
        $risk_label  = $score >= 70 ? 'HIGH RISK' : ( $score >= 40 ? 'MEDIUM RISK' : 'LOW RISK' );
        $risk_color  = $score >= 70 ? '#c0392b'   : ( $score >= 40 ? '#a07800'     : '#2e7d32' );
        $scan_date   = date( 'F j, Y  H:i', strtotime( $scan->created_at ) );
        $target      = esc_html( $scan->target_url );
        $ai_summary  = $scan->ai_summary ? nl2br( esc_html( $scan->ai_summary ) ) : '';

        ob_start();
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — <?php echo $target; ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg:       #f5f4f0;
  --surface:  #ffffff;
  --border:   #d4d2cc;
  --border2:  #e8e6e1;
  --text:     #111110;
  --ink:      #2a2927;
  --muted:    #787670;
  --critical: #c0392b;
  --high:     #c0630b;
  --medium:   #a07800;
  --low:      #2e7d32;
  --info:     #1565c0;
  --f-sans:   'DM Sans', system-ui, sans-serif;
  --f-mono:   'IBM Plex Mono', monospace;
  --r:        3px;
}
body { font-family: var(--f-sans); background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.6; }
.wrap { max-width: 900px; margin: 0 auto; padding: 48px 40px; }

/* Report header */
.rpt-header {
  display: grid; grid-template-columns: 1fr auto;
  gap: 32px; align-items: end;
  padding-bottom: 32px; margin-bottom: 32px;
  border-bottom: 2px solid var(--text);
}
.rpt-tagline { font-family: var(--f-mono); font-size: 10px; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted); margin-bottom: 10px; }
.rpt-title   { font-size: 30px; font-weight: 600; letter-spacing: -0.5px; line-height: 1.15; }
.rpt-meta    { font-family: var(--f-mono); font-size: 12px; color: var(--muted); margin-top: 10px; }
.rpt-meta span { display: block; margin-top: 3px; }
.rpt-score-block { text-align: right; }
.rpt-score-num   { font-family: var(--f-mono); font-size: 72px; font-weight: 600; line-height: 1; letter-spacing: -3px; color: <?php echo $risk_color; ?>; }
.rpt-risk-label  { font-family: var(--f-mono); font-size: 10px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: <?php echo $risk_color; ?>; text-align: right; margin-top: 4px; }
.rpt-score-sub   { font-family: var(--f-mono); font-size: 10px; color: var(--muted); text-align: right; }

/* Stat row */
.stat-row { display: flex; border: 1px solid var(--border); border-radius: var(--r); overflow: hidden; margin-bottom: 32px; }
.stat-cell { flex: 1; text-align: center; padding: 16px 10px; border-right: 1px solid var(--border); }
.stat-cell:last-child { border-right: none; }
.stat-n { font-family: var(--f-mono); font-size: 28px; font-weight: 600; line-height: 1; }
.stat-l { font-family: var(--f-mono); font-size: 9px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); margin-top: 4px; }
.s-critical .stat-n { color: var(--critical); } .s-high .stat-n { color: var(--high); }
.s-medium   .stat-n { color: var(--medium); }   .s-low  .stat-n { color: var(--low); }
.s-info     .stat-n { color: var(--info); }

/* Section */
.section       { margin-bottom: 36px; }
.section-title { font-family: var(--f-mono); font-size: 9px; font-weight: 600; letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted); margin-bottom: 14px; padding-bottom: 10px; border-bottom: 1px solid var(--border2); }

/* AI summary */
.ai-summary { background: var(--surface); border: 1px solid var(--border2); border-left: 3px solid var(--text); border-radius: 0 var(--r) var(--r) 0; padding: 18px 22px; font-size: 14px; line-height: 1.75; color: var(--ink); }

/* Findings */
.finding { background: var(--surface); border: 1px solid var(--border2); border-radius: var(--r); margin-bottom: 8px; overflow: hidden; }
.finding-head { display: flex; align-items: center; gap: 14px; padding: 13px 18px; cursor: pointer; }
.finding-head:hover { background: var(--bg); }
.sev-badge { font-family: var(--f-mono); font-size: 9px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; padding: 2px 7px; border-radius: 2px; border: 1px solid; white-space: nowrap; }
.sev-critical { color: var(--critical); border-color: var(--critical); background: rgba(192,57,43,0.06); }
.sev-high     { color: var(--high);     border-color: var(--high);     background: rgba(192,99,11,0.06); }
.sev-medium   { color: var(--medium);   border-color: var(--medium);   background: rgba(160,120,0,0.06); }
.sev-low      { color: var(--low);      border-color: var(--low);      background: rgba(46,125,50,0.06); }
.sev-info     { color: var(--info);     border-color: var(--info);     background: rgba(21,101,192,0.06); }
.finding-title { flex: 1; font-size: 13px; font-weight: 500; }
.finding-type  { font-family: var(--f-mono); font-size: 10px; color: var(--muted); }
.toggle        { font-family: var(--f-mono); color: var(--muted); font-size: 14px; }
.finding-body  { display: none; padding: 0 18px 18px; }
.finding-body.open { display: block; }
.fdivider      { height: 1px; background: var(--border2); margin: 0 0 14px; }
.fsec          { margin-top: 14px; }
.fsec-label    { font-family: var(--f-mono); font-size: 9px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); margin-bottom: 6px; }
.fsec-text     { font-size: 13px; line-height: 1.65; color: var(--ink); }
.evidence      { font-family: var(--f-mono); font-size: 11px; background: var(--bg); border: 1px solid var(--border2); border-radius: var(--r); padding: 10px 14px; color: #2e7d32; white-space: pre-wrap; word-break: break-all; }
.ai-detail     { background: var(--bg); border: 1px solid var(--border2); border-left: 3px solid var(--text); border-radius: 0 var(--r) var(--r) 0; padding: 14px 18px; font-size: 12px; line-height: 1.75; color: var(--ink); white-space: pre-wrap; font-family: var(--f-mono); }

/* Footer */
.rpt-footer { border-top: 1px solid var(--border); margin-top: 48px; padding-top: 20px; display: flex; justify-content: space-between; font-family: var(--f-mono); font-size: 11px; color: var(--muted); }

@media print {
  body { background: white; }
  .finding-body { display: block !important; }
  .toggle { display: none; }
  .finding-head { cursor: default; }
}
</style>
</head>
<body>
<div class="wrap">

  <div class="rpt-header">
    <div>
      <div class="rpt-tagline">WP Security Scanner Pro — Vulnerability Assessment</div>
      <h1 class="rpt-title">Security Report</h1>
      <div class="rpt-meta">
        <span>Target: <?php echo $target; ?></span>
        <span>Date: <?php echo esc_html( $scan_date ); ?></span>
        <span>Scan ID: #<?php echo intval( $scan_id ); ?></span>
      </div>
    </div>
    <div class="rpt-score-block">
      <div class="rpt-score-num"><?php echo $score; ?></div>
      <div class="rpt-risk-label"><?php echo esc_html( $risk_label ); ?></div>
      <div class="rpt-score-sub">/ 100</div>
    </div>
  </div>

  <div class="stat-row">
    <?php foreach ( $counts as $sev => $n ) : ?>
    <div class="stat-cell s-<?php echo $sev; ?>">
      <div class="stat-n"><?php echo $n; ?></div>
      <div class="stat-l"><?php echo ucfirst( $sev ); ?></div>
    </div>
    <?php endforeach; ?>
  </div>

  <?php if ( $ai_summary ) : ?>
  <div class="section">
    <div class="section-title">AI Executive Summary</div>
    <div class="ai-summary"><?php echo $ai_summary; ?></div>
  </div>
  <?php endif; ?>

  <div class="section">
    <div class="section-title">Findings (<?php echo count( $results ); ?>)</div>
    <?php foreach ( $results as $i => $r ) : ?>
    <div class="finding">
      <div class="finding-head" onclick="toggle(<?php echo $i; ?>)">
        <span class="sev-badge sev-<?php echo esc_attr( $r->severity ); ?>"><?php echo strtoupper( $r->severity ); ?></span>
        <span class="finding-title"><?php echo esc_html( $r->title ); ?></span>
        <span class="finding-type"><?php echo esc_html( strtoupper( $r->test_type ) ); ?></span>
        <span class="toggle" id="t<?php echo $i; ?>">+</span>
      </div>
      <div class="finding-body" id="b<?php echo $i; ?>">
        <div class="fdivider"></div>
        <div class="fsec"><div class="fsec-label">Description</div><div class="fsec-text"><?php echo wp_kses_post( $r->description ); ?></div></div>
        <?php if ( ! empty( $r->evidence ) ) : ?>
        <div class="fsec"><div class="fsec-label">Evidence</div><div class="evidence"><?php echo esc_html( $r->evidence ); ?></div></div>
        <?php endif; ?>
        <?php if ( ! empty( $r->remediation ) ) : ?>
        <div class="fsec"><div class="fsec-label">Remediation</div><div class="fsec-text"><?php echo wp_kses_post( $r->remediation ); ?></div></div>
        <?php endif; ?>
        <?php if ( ! empty( $r->ai_analysis ) ) : ?>
        <div class="fsec"><div class="fsec-label">AI Analysis</div><div class="ai-detail"><?php echo nl2br( esc_html( $r->ai_analysis ) ); ?></div></div>
        <?php endif; ?>
      </div>
    </div>
    <?php endforeach; ?>
  </div>

  <div class="rpt-footer">
    <span>WP Security Scanner Pro</span>
    <span>Scan #<?php echo intval( $scan_id ); ?> &middot; <?php echo esc_html( $scan_date ); ?></span>
  </div>
</div>

<script>
function toggle(i) {
  var b = document.getElementById('b'+i);
  var t = document.getElementById('t'+i);
  var open = b.classList.contains('open');
  b.classList.toggle('open', !open);
  t.textContent = open ? '+' : '−';
}
// Auto-open critical + high
<?php foreach ( $results as $i => $r ) :
  if ( in_array( $r->severity, array( 'critical', 'high' ) ) ) : ?>
toggle(<?php echo $i; ?>);
<?php endif; endforeach; ?>
</script>
</body>
</html>
        <?php
        return ob_get_clean();
    }
}
