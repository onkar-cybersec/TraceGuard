import { sanitizeText } from './redaction';
import { RULE_DEFINITIONS } from './rules';
import { DetectionFinding, DetectionResult, ValidationSummary } from './types';

/**
 * Safely escape string content for secure HTML embedding.
 * Prevents XSS and HTML injection.
 */
export function escapeHtml(str: unknown): string {
  if (str === null || str === undefined) return '';
  const s = String(str);
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Generate sanitized, redacted JSON export.
 * Excludes raw unredacted original logs.
 */
export function generateRedactedJsonExport(result: DetectionResult): string {
  const exportPayload = {
    generator: 'TraceGuard Security Log Investigation Console',
    version: '1.0.0',
    analysis_timestamp_utc: result.validation.analysis_timestamp_utc,
    metadata: {
      source_file: sanitizeText(result.validation.file_name),
      file_size_bytes: result.validation.file_size_bytes,
      total_rows: result.validation.total_rows,
      valid_events: result.validation.valid_count,
      rejected_rows: result.validation.rejected_count,
      earliest_event_utc: result.validation.earliest_event_utc || null,
      latest_event_utc: result.validation.latest_event_utc || null,
    },
    validation_rejected_records: result.validation.rejected_rows.map((r) => ({
      row_number: r.row_number,
      error: sanitizeText(r.error),
      preview: sanitizeText(r.raw_content),
    })),
    detection_summary: {
      total_findings: result.findings.length,
      severity_breakdown: {
        critical: result.findings.filter((f) => f.severity === 'critical').length,
        high: result.findings.filter((f) => f.severity === 'high').length,
        medium: result.findings.filter((f) => f.severity === 'medium').length,
        low: result.findings.filter((f) => f.severity === 'low').length,
      },
    },
    findings: result.findings.map((f) => ({
      finding_id: f.id,
      rule_id: f.rule_id,
      rule_title: f.rule_title,
      category: f.category,
      severity: f.severity,
      summary: f.summary,
      explanation: f.explanation,
      entity_user: f.entity_user || null,
      entity_source_ip: f.entity_source_ip || null,
      first_seen_utc: f.first_seen_utc,
      last_seen_utc: f.last_seen_utc,
      trigger_event_ids: f.trigger_event_ids,
      caveat_notice: f.caveat_notice,
      suggested_investigation_steps: f.suggested_investigation_steps,
      supporting_redacted_events: f.supporting_events.map((e) => ({
        id: e.id,
        timestamp_utc: e.timestamp,
        event_type: e.event_type,
        user: e.user || null,
        source_ip: e.source_ip || null,
        destination_ip: e.destination_ip || null,
        destination_port: e.destination_port || null,
        bytes: e.bytes !== undefined ? e.bytes : null,
        status: e.status || null,
        new_role: e.new_role || null,
        message: e.message || null,
        has_redacted_secret: e.has_redacted_secret || false,
      })),
    })),
    redacted_event_stream: result.events.map((e) => ({
      id: e.id,
      timestamp: e.timestamp,
      event_type: e.event_type,
      user: e.user || null,
      source_ip: e.source_ip || null,
      destination_ip: e.destination_ip || null,
      destination_port: e.destination_port || null,
      bytes: e.bytes !== undefined ? e.bytes : null,
      status: e.status || null,
      new_role: e.new_role || null,
      message: e.message || null,
    })),
    disclaimer:
      'All values processed and exported have undergone pattern-based secret redaction. Detections are deterministic behavioral indicators and require SOC analyst verification against authorized change tickets and business context.',
  };

  return JSON.stringify(exportPayload, null, 2);
}

/**
 * Generate a standalone, self-contained HTML report with strict escaping.
 */
export function generateSelfContainedHtmlReport(
  validation: ValidationSummary,
  findings: DetectionFinding[]
): string {
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;
  const lowCount = findings.filter((f) => f.severity === 'low').length;

  const ruleTableRows = Object.values(RULE_DEFINITIONS)
    .map(
      (r) => `
      <tr>
        <td style="font-family: monospace; font-weight: 600; color: #14b8a6;">${escapeHtml(r.id)}</td>
        <td style="font-weight: 500;">${escapeHtml(r.name)}</td>
        <td><span class="badge badge-${escapeHtml(r.severity)}">${escapeHtml(r.severity.toUpperCase())}</span></td>
        <td style="font-size: 13px; color: #94a3b8;">${escapeHtml(r.threshold_summary)}</td>
      </tr>`
    )
    .join('');

  let findingsSectionHtml = '';

  if (findings.length === 0) {
    findingsSectionHtml = `
      <div class="empty-state">
        <h3 style="color: #10b981; margin-top: 0;">No Rule Triggers Identified</h3>
        <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6;">
          Zero automated rule thresholds were reached in the analyzed dataset.
        </p>
        <div class="notice-box">
          <strong>Mandatory Investigative Notice:</strong>
          The absence of triggered findings does <em>not</em> prove that the audited system is secure, uncompromised, or free of malicious activity. Advanced threats, authorized credential abuse, stealthy low-frequency activity, or unmonitored attack vectors may have occurred outside these specific behavioral threshold rules.
        </div>
      </div>
    `;
  } else {
    findingsSectionHtml = findings
      .map((f, idx) => {
        const eventsTableRows = f.supporting_events
          .map(
            (evt) => `
            <tr>
              <td style="font-family: monospace; color: #38bdf8;">${escapeHtml(evt.id)}</td>
              <td style="font-family: monospace; font-size: 12px;">${escapeHtml(evt.timestamp)}</td>
              <td><strong>${escapeHtml(evt.event_type)}</strong></td>
              <td style="font-family: monospace;">${escapeHtml(evt.user || '—')}</td>
              <td style="font-family: monospace;">${escapeHtml(evt.source_ip || '—')}</td>
              <td style="font-family: monospace;">${escapeHtml(evt.destination_ip || '—')}${evt.destination_port ? `:${escapeHtml(evt.destination_port)}` : ''}</td>
              <td style="font-size: 12px; color: #cbd5e1;">${escapeHtml(evt.message || evt.new_role || evt.status || '—')}</td>
            </tr>`
          )
          .join('');

        const stepsList = f.suggested_investigation_steps
          .map((s) => `<li>${escapeHtml(s)}</li>`)
          .join('');

        return `
          <div class="finding-card">
            <div class="finding-header">
              <div>
                <span class="badge badge-${escapeHtml(f.severity)}">${escapeHtml(f.severity.toUpperCase())}</span>
                <span style="font-family: monospace; color: #14b8a6; margin-left: 8px; font-weight: 600;">${escapeHtml(f.rule_id)}</span>
                <span style="color: #64748b; margin: 0 6px;">·</span>
                <span style="color: #cbd5e1; font-size: 14px;">${escapeHtml(f.category)}</span>
              </div>
              <span style="font-family: monospace; font-size: 12px; color: #94a3b8;">#${idx + 1} (${escapeHtml(f.id)})</span>
            </div>

            <h3 style="margin: 12px 0 6px 0; font-size: 18px; color: #f8fafc;">${escapeHtml(f.summary)}</h3>
            <p style="color: #94a3b8; font-size: 14px; line-height: 1.5; margin-bottom: 16px;">
              ${escapeHtml(f.explanation)}
            </p>

            <div class="metadata-grid">
              <div>
                <div class="meta-label">Impacted User</div>
                <div class="meta-val">${escapeHtml(f.entity_user || 'N/A')}</div>
              </div>
              <div>
                <div class="meta-label">Source IP</div>
                <div class="meta-val">${escapeHtml(f.entity_source_ip || 'N/A')}</div>
              </div>
              <div>
                <div class="meta-label">Observation Window (UTC)</div>
                <div class="meta-val" style="font-size: 12px;">${escapeHtml(f.first_seen_utc)} &rarr; ${escapeHtml(f.last_seen_utc)}</div>
              </div>
              <div>
                <div class="meta-label">Supporting Events</div>
                <div class="meta-val">${f.supporting_events.length} events</div>
              </div>
            </div>

            <div class="caveat-box">
              <strong>Context & Legitimate Explanations:</strong>
              ${escapeHtml(f.caveat_notice)}
            </div>

            <h4 style="margin: 18px 0 8px 0; font-size: 14px; color: #f1f5f9; text-transform: uppercase; letter-spacing: 0.05em;">
              Recommended Investigation Steps
            </h4>
            <ul class="steps-list">
              ${stepsList}
            </ul>

            <h4 style="margin: 18px 0 8px 0; font-size: 14px; color: #f1f5f9; text-transform: uppercase; letter-spacing: 0.05em;">
              Redacted Supporting Event Evidence (${f.supporting_events.length})
            </h4>
            <div style="overflow-x: auto;">
              <table class="evidence-table">
                <thead>
                  <tr>
                    <th>Event ID</th>
                    <th>Timestamp (UTC)</th>
                    <th>Type</th>
                    <th>User</th>
                    <th>Source IP</th>
                    <th>Dest IP:Port</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  ${eventsTableRows}
                </tbody>
              </table>
            </div>
          </div>
        `;
      })
      .join('');
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TraceGuard Security Audit Report — ${escapeHtml(validation.file_name)}</title>
  <style>
    :root {
      color-scheme: dark;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #0b0f19;
      color: #e2e8f0;
      margin: 0;
      padding: 32px 24px;
      line-height: 1.5;
    }
    .container {
      max-width: 1140px;
      margin: 0 auto;
    }
    header {
      border-bottom: 1px solid #1e293b;
      padding-bottom: 24px;
      margin-bottom: 28px;
    }
    .brand-title {
      font-size: 26px;
      font-weight: 700;
      color: #f8fafc;
      letter-spacing: -0.02em;
      margin: 0 0 6px 0;
    }
    .brand-sub {
      color: #94a3b8;
      font-size: 14px;
      margin: 0;
    }
    .summary-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }
    .card {
      background-color: #111827;
      border: 1px solid #1f2937;
      border-radius: 8px;
      padding: 16px 20px;
    }
    .card-label {
      font-size: 12px;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 6px;
    }
    .card-val {
      font-size: 28px;
      font-weight: 700;
      color: #f8fafc;
      font-family: monospace;
    }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
    .badge-critical { background-color: #7f1d1d; color: #fecaca; }
    .badge-high { background-color: #7c2d12; color: #fed7aa; }
    .badge-medium { background-color: #78350f; color: #fde68a; }
    .badge-low { background-color: #14532d; color: #bbf7d0; }

    .section-title {
      font-size: 20px;
      font-weight: 600;
      color: #f1f5f9;
      margin: 36px 0 16px 0;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid #1f2937;
    }
    th {
      background-color: #111827;
      color: #94a3b8;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.05em;
    }
    .finding-card {
      background-color: #111827;
      border: 1px solid #1f2937;
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 24px;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #1f2937;
      padding-bottom: 12px;
    }
    .metadata-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      background-color: #0b0f19;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 12px 16px;
      margin: 16px 0;
    }
    .meta-label {
      font-size: 11px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .meta-val {
      font-size: 13px;
      color: #f8fafc;
      font-family: monospace;
      margin-top: 2px;
    }
    .caveat-box {
      background-color: rgba(20, 184, 166, 0.08);
      border-left: 3px solid #14b8a6;
      padding: 12px 16px;
      font-size: 13px;
      color: #cbd5e1;
      border-radius: 0 6px 6px 0;
      margin: 16px 0;
    }
    .steps-list {
      margin: 0;
      padding-left: 20px;
      font-size: 13px;
      color: #cbd5e1;
    }
    .steps-list li {
      margin-bottom: 6px;
    }
    .evidence-table {
      margin-top: 10px;
      background-color: #0b0f19;
      border: 1px solid #1e293b;
      border-radius: 6px;
    }
    .notice-box {
      background-color: #1e293b;
      border-left: 3px solid #38bdf8;
      padding: 14px 18px;
      margin-top: 16px;
      border-radius: 0 6px 6px 0;
      font-size: 13px;
    }
    .empty-state {
      background-color: #111827;
      border: 1px solid #1f2937;
      border-radius: 8px;
      padding: 32px;
      text-align: center;
    }
    footer {
      border-top: 1px solid #1e293b;
      padding-top: 24px;
      margin-top: 48px;
      font-size: 12px;
      color: #64748b;
      line-height: 1.6;
    }
    @media print {
      body {
        background-color: #ffffff;
        color: #0f172a;
      }
      .card, .finding-card {
        border: 1px solid #cbd5e1;
        background-color: #ffffff;
      }
      .metadata-grid, .evidence-table {
        background-color: #f8fafc;
        border: 1px solid #cbd5e1;
      }
      th {
        background-color: #f1f5f9;
        color: #475569;
      }
      td, .meta-val, .card-val {
        color: #0f172a;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1 class="brand-title">TraceGuard Security Investigation Report</h1>
      <p class="brand-sub">
        Source Target: <strong>${escapeHtml(validation.file_name)}</strong> ·
        Generated: <span style="font-family: monospace;">${escapeHtml(validation.analysis_timestamp_utc)}</span> ·
        Classification: Internal Security Telemetry
      </p>
    </header>

    <div class="summary-cards">
      <div class="card">
        <div class="card-label">Total Logs Analyzed</div>
        <div class="card-val">${validation.total_rows.toLocaleString()}</div>
      </div>
      <div class="card">
        <div class="card-label">Valid Events</div>
        <div class="card-val" style="color: #10b981;">${validation.valid_count.toLocaleString()}</div>
      </div>
      <div class="card">
        <div class="card-label">Rejected Rows</div>
        <div class="card-val" style="color: ${validation.rejected_count > 0 ? '#f59e0b' : '#94a3b8'};">${validation.rejected_count.toLocaleString()}</div>
      </div>
      <div class="card">
        <div class="card-label">Triggered Findings</div>
        <div class="card-val" style="color: ${findings.length > 0 ? '#f43f5e' : '#10b981'};">${findings.length.toLocaleString()}</div>
      </div>
    </div>

    <div style="display: flex; gap: 12px; margin-bottom: 24px; font-size: 13px;">
      <span class="badge badge-critical">Critical: ${criticalCount}</span>
      <span class="badge badge-high">High: ${highCount}</span>
      <span class="badge badge-medium">Medium: ${mediumCount}</span>
      <span class="badge badge-low">Low: ${lowCount}</span>
    </div>

    <h2 class="section-title">Detection Rule Inventory & Thresholds</h2>
    <table style="background: #111827; border: 1px solid #1f2937; border-radius: 8px; margin-bottom: 32px;">
      <thead>
        <tr>
          <th>Rule ID</th>
          <th>Rule Name</th>
          <th>Severity</th>
          <th>Threshold Specification</th>
        </tr>
      </thead>
      <tbody>
        ${ruleTableRows}
      </tbody>
    </table>

    ${validation.rejected_rows && validation.rejected_rows.length > 0 ? `
    <h2 class="section-title">Validation Exceptions & Rejected Records (${validation.rejected_count})</h2>
    <table style="background: #111827; border: 1px solid #1f2937; border-radius: 8px; margin-bottom: 32px;">
      <thead>
        <tr>
          <th>Row #</th>
          <th>Validation Error</th>
          <th>Raw Preview (Sanitized)</th>
        </tr>
      </thead>
      <tbody>
        ${validation.rejected_rows
          .map(
            (r) => `
          <tr>
            <td style="font-family: monospace; font-weight: 600;">#${r.row_number}</td>
            <td style="color: #f87171;">${escapeHtml(sanitizeText(r.error))}</td>
            <td style="font-family: monospace; font-size: 12px; color: #94a3b8;">${escapeHtml(sanitizeText(r.raw_content))}</td>
          </tr>`
          )
          .join('')}
      </tbody>
    </table>` : ''}

    <h2 class="section-title">Correlated Findings & Investigative Evidence (${findings.length})</h2>
    ${findingsSectionHtml}

    <footer>
      <p>
        <strong>Legal & Technical Limitations:</strong>
        TraceGuard operates client-side deterministic behavioral heuristics designed to accelerate Tier-1 Security Operations Center (SOC) triage. The presence of a finding does not constitute definitive proof of intrusion or malicious intent; conversely, the absence of findings does not certify that systems are secure or devoid of unauthorized activity.
      </p>
      <p>
        All log data displayed in this report has undergone automated best-effort pattern redaction to scrub AWS credentials, private key headers, bearer authentication tokens, and password assignments. Original unredacted payloads are permanently excluded from exports.
      </p>
    </footer>
  </div>
</body>
</html>`;
}