/* jshint esversion: 6 */
(function ($) {
  'use strict';

  const WPSS = window.WPSS || {};

  // ─── Progress ────────────────────────────────────────────────────
  const steps = [
    'Resolving target host',
    'Checking SSL / TLS certificate',
    'Analysing security headers',
    'Testing XSS vectors',
    'Probing SQL injection endpoints',
    'Running pen-test reconnaissance',
    'Requesting AI analysis',
    'Compiling report',
  ];

  let timer = null, step = 0;

  function startProgress() {
    step = 0;
    setProgress(steps[0], 4);
    timer = setInterval(function () {
      step++;
      if (step < steps.length) setProgress(steps[step], Math.round((step / steps.length) * 82));
    }, 4200);
  }

  function stopProgress(pct, msg) {
    clearInterval(timer);
    setProgress(msg || 'Complete', pct || 100);
  }

  function setProgress(msg, pct) {
    $('#wpss-progress-text').text(msg);
    $('#wpss-progress-pct').text(pct + '%');
    $('#wpss-progress-bar').css('width', pct + '%');
  }

  // ─── Run scan ────────────────────────────────────────────────────
  $(document).on('click', '#wpss-run-btn', function () {
    const $btn  = $(this);
    const url   = $('#wpss-target-url').val().trim();
    const tests = [];
    $('.wpss-module-check:checked').each(function () { tests.push($(this).val()); });

    if (!url)         { alert('Please enter a target URL.'); return; }
    if (!tests.length){ alert('Please select at least one module.'); return; }

    $btn.prop('disabled', true).text('Scanning...');
    $('#wpss-progress').show();
    $('#wpss-results-container').empty();
    startProgress();

    $.ajax({
      url:     WPSS.ajax_url,
      type:    'POST',
      timeout: 300000,
      data:    { action: 'wpss_run_scan', nonce: WPSS.nonce, url: url, tests: tests },
      success: function (resp) {
        stopProgress(100, 'Scan complete');
        setTimeout(function () {
          $('#wpss-progress').hide();
          resp.success ? renderResults(resp.data) : renderError(resp.data || 'Unknown error');
        }, 600);
      },
      error: function (xhr, status) {
        stopProgress(0, 'Scan failed');
        $('#wpss-progress').hide();
        renderError('Request failed (' + status + '). The scan may have timed out — try fewer modules.');
      },
      complete: function () { $btn.prop('disabled', false).text('Run Scan'); },
    });
  });

  // ─── Render results ──────────────────────────────────────────────
  function renderResults(data) {
    const results = data.results || [];
    const cnt = { critical:0, high:0, medium:0, low:0, info:0 };
    results.forEach(r => { if (cnt[r.severity] !== undefined) cnt[r.severity]++; });

    const score  = data.risk_score || 0;
    const scls   = score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';
    const scanId = data.scan_id;

    let html = `<div class="wpss-panel">
      <div class="wpss-score-block wpss-score-${scls}">
        <div>
          <div class="wpss-score-num">${score}</div>
          <div class="wpss-score-sub">Risk Score &middot; Scan #${scanId}</div>
        </div>
        <button class="wpss-btn-ghost wpss-view-report" data-scan-id="${scanId}">View Report</button>
      </div>

      <div class="wpss-stat-row">
        ${['critical','high','medium','low','info'].map(s =>
          `<div class="wpss-stat-cell s-${s}">
            <div class="wpss-stat-n">${cnt[s]}</div>
            <div class="wpss-stat-l">${s.charAt(0).toUpperCase()+s.slice(1)}</div>
          </div>`).join('')}
      </div>`;

    if (data.ai_summary) {
      html += `<div style="margin-top:24px;">
        <div class="wpss-ai-label">AI Summary</div>
        <div class="wpss-ai-summary">${esc(data.ai_summary)}</div>
      </div>`;
    }

    html += `<div class="wpss-findings-label">Findings (${results.length})</div>
      <div id="wpss-findings">
        ${results.map((r,i) => buildFinding(r,i)).join('')}
      </div>
    </div>`;

    $('#wpss-results-container').html(html);

    // Auto-expand critical/high
    results.forEach((r,i) => { if (r.severity === 'critical' || r.severity === 'high') openFinding(i); });
  }

  function buildFinding(r, i) {
    const ev  = r.evidence    ? `<div class="wpss-fsec"><div class="wpss-fsec-label">Evidence</div><div class="wpss-evidence">${esc(r.evidence)}</div></div>` : '';
    const rem = r.remediation ? `<div class="wpss-fsec"><div class="wpss-fsec-label">Remediation</div><div class="wpss-fsec-text">${esc(r.remediation)}</div></div>` : '';
    const ai  = r.ai_analysis ? `<div class="wpss-fsec"><div class="wpss-fsec-label">AI Analysis</div><div class="wpss-ai-detail">${esc(r.ai_analysis)}</div></div>` : '';

    return `<div class="wpss-finding">
      <div class="wpss-finding-head" data-idx="${i}">
        <span class="wpss-sev sev-${r.severity}">${r.severity.toUpperCase()}</span>
        <span class="wpss-finding-title">${esc(r.title)}</span>
        <span class="wpss-finding-type">${(r.test_type||'').toUpperCase()}</span>
        <span class="wpss-toggle-icon" id="wtog-${i}">+</span>
      </div>
      <div class="wpss-finding-body" id="wbody-${i}">
        <div class="wpss-finding-divider"></div>
        <div class="wpss-fsec"><div class="wpss-fsec-label">Description</div><div class="wpss-fsec-text">${esc(r.description)}</div></div>
        ${ev}${rem}${ai}
      </div>
    </div>`;
  }

  function openFinding(i) {
    $('#wbody-'+i).addClass('is-open');
    $('#wtog-'+i).text('−');
  }

  $(document).on('click', '.wpss-finding-head', function () {
    const i    = $(this).data('idx');
    const open = $('#wbody-'+i).hasClass('is-open');
    $('#wbody-'+i).toggleClass('is-open', !open);
    $('#wtog-'+i).text(open ? '+' : '−');
  });

  // ─── Report modal ─────────────────────────────────────────────────
  $(document).on('click', '.wpss-view-report', function () {
    const id = $(this).data('scan-id');
    $('#wpss-report-modal').show();
    $('body').css('overflow', 'hidden');
    $('#wpss-report-frame').attr('src', 'about:blank');

    $.ajax({
      url:  WPSS.ajax_url,
      type: 'POST',
      data: { action: 'wpss_get_report', nonce: WPSS.nonce, scan_id: id },
      success: function (resp) {
        if (!resp.success) return;
        const doc = $('#wpss-report-frame')[0].contentDocument;
        doc.open(); doc.write(resp.data.html); doc.close();
      },
    });
  });

  $(document).on('click', '#wpss-close-modal, #wpss-modal-backdrop', function () {
    $('#wpss-report-modal').hide();
    $('body').css('overflow', '');
  });

  $(document).on('click', '#wpss-print-btn', function () {
    const f = $('#wpss-report-frame')[0];
    if (f && f.contentWindow) f.contentWindow.print();
  });

  // ─── Error ────────────────────────────────────────────────────────
  function renderError(msg) {
    $('#wpss-results-container').html(
      `<div class="wpss-panel wpss-error-panel">
        <div class="wpss-error-title">Scan Error</div>
        <div class="wpss-fsec-text">${esc(msg)}</div>
      </div>`
    );
  }

  function esc(s) {
    return String(s||'')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#039;').replace(/\n/g,'<br>');
  }

}(jQuery));
