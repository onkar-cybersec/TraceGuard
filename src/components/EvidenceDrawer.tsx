import { AlertCircle, CheckCircle, Clock, ExternalLink, ShieldAlert, X } from 'lucide-react';
import React, { useEffect, useState } from 'react';
import { DetectionFinding } from '../engine/types';

interface EvidenceDrawerProps {
  finding: DetectionFinding | null;
  onClose: () => void;
}

export const EvidenceDrawer: React.FC<EvidenceDrawerProps> = ({ finding, onClose }) => {
  const [activeTab, setActiveTab] = useState<'events' | 'raw_json' | 'playbook'>('events');

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!finding) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-slate-950/70 backdrop-blur-sm transition-opacity"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl h-full bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col overflow-hidden text-slate-100"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="border-b border-slate-800 px-6 py-4 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2">
            <span
              className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                finding.severity === 'critical'
                  ? 'text-rose-400 bg-rose-950/80 border border-rose-800'
                  : finding.severity === 'high'
                  ? 'text-amber-400 bg-amber-950/80 border border-amber-800'
                  : finding.severity === 'medium'
                  ? 'text-yellow-400 bg-yellow-950/80 border border-yellow-800'
                  : 'text-emerald-400 bg-emerald-950/80 border border-emerald-800'
              }`}
            >
              {finding.severity}
            </span>
            <span className="font-mono text-sm font-semibold text-teal-400">
              {finding.rule_id}
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-xs text-slate-300 font-medium">{finding.rule_title}</span>
          </div>

          <button
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors cursor-pointer"
            aria-label="Close drawer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
          {/* Title & Summary */}
          <div>
            <h3 className="text-lg font-bold text-slate-100 leading-snug">
              {finding.summary}
            </h3>
            <p className="mt-2 text-xs sm:text-sm text-slate-300 leading-relaxed">
              {finding.explanation}
            </p>
          </div>

          {/* Investigation Caveat Box (Mandatory heuristic disclaimer) */}
          <div className="rounded-lg border border-teal-900/60 bg-teal-950/20 p-4 space-y-1.5 text-xs">
            <div className="font-semibold text-teal-300 flex items-center gap-1.5">
              <AlertCircle className="h-4 w-4 text-teal-400" />
              Heuristic Explanation & Legitimate Causes
            </div>
            <p className="text-slate-300 leading-relaxed">{finding.caveat_notice}</p>
          </div>

          {/* Incident Telemetry Metadata Grid */}
          <div className="grid grid-cols-2 gap-3 rounded-lg border border-slate-800 bg-slate-950/60 p-4 text-xs font-mono">
            <div>
              <div className="text-[10px] text-slate-500 uppercase font-sans">Entity User</div>
              <div className="text-slate-200 font-medium mt-0.5">
                {finding.entity_user || '—'}
              </div>
            </div>
            <div>
              <div className="text-[10px] text-slate-500 uppercase font-sans">Source IP</div>
              <div className="text-slate-200 font-medium mt-0.5">
                {finding.entity_source_ip || '—'}
              </div>
            </div>
            <div>
              <div className="text-[10px] text-slate-500 uppercase font-sans">First Observed (UTC)</div>
              <div className="text-slate-400 mt-0.5">{finding.first_seen_utc}</div>
            </div>
            <div>
              <div className="text-[10px] text-slate-500 uppercase font-sans">Last Observed (UTC)</div>
              <div className="text-slate-400 mt-0.5">{finding.last_seen_utc}</div>
            </div>
          </div>

          {/* Evidence Tabs */}
          <div>
            <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
              <button
                onClick={() => setActiveTab('events')}
                className={`text-xs font-semibold py-1 px-2.5 rounded cursor-pointer transition-colors ${
                  activeTab === 'events'
                    ? 'bg-slate-800 text-teal-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Supporting Events ({finding.supporting_events.length})
              </button>
              <button
                onClick={() => setActiveTab('playbook')}
                className={`text-xs font-semibold py-1 px-2.5 rounded cursor-pointer transition-colors ${
                  activeTab === 'playbook'
                    ? 'bg-slate-800 text-teal-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                SOC Playbook Steps
              </button>
              <button
                onClick={() => setActiveTab('raw_json')}
                className={`text-xs font-semibold py-1 px-2.5 rounded cursor-pointer transition-colors ${
                  activeTab === 'raw_json'
                    ? 'bg-slate-800 text-teal-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Redacted JSON Payload
              </button>
            </div>

            <div className="mt-4">
              {activeTab === 'events' && (
                <div className="space-y-3">
                  {finding.supporting_events.map((evt, idx) => (
                    <div
                      key={evt.id || idx}
                      className="rounded border border-slate-800 bg-slate-950/80 p-3 space-y-2 text-xs"
                    >
                      <div className="flex items-center justify-between text-[11px] font-mono border-b border-slate-850 pb-1.5 text-slate-400">
                        <span className="text-teal-400 font-semibold">{evt.id}</span>
                        <span>{evt.timestamp}</span>
                      </div>

                      <div className="grid grid-cols-2 gap-2 text-slate-300 font-mono text-[11px]">
                        <div>
                          <span className="text-slate-500 font-sans">Type:</span> {evt.event_type}
                        </div>
                        <div>
                          <span className="text-slate-500 font-sans">Status:</span>{' '}
                          <span
                            className={
                              evt.status === 'failure'
                                ? 'text-rose-400 font-semibold'
                                : evt.status === 'success'
                                ? 'text-emerald-400'
                                : 'text-slate-300'
                            }
                          >
                            {evt.status || '—'}
                          </span>
                        </div>
                        {evt.source_ip && (
                          <div>
                            <span className="text-slate-500 font-sans">Source IP:</span> {evt.source_ip}
                          </div>
                        )}
                        {evt.destination_ip && (
                          <div>
                            <span className="text-slate-500 font-sans">Dest IP:</span> {evt.destination_ip}
                            {evt.destination_port ? `:${evt.destination_port}` : ''}
                          </div>
                        )}
                        {evt.bytes !== undefined && (
                          <div>
                            <span className="text-slate-500 font-sans">Bytes:</span>{' '}
                            {evt.bytes.toLocaleString()} ({((evt.bytes) / (1024 * 1024)).toFixed(2)} MiB)
                          </div>
                        )}
                        {evt.new_role && (
                          <div>
                            <span className="text-slate-500 font-sans">Role:</span>{' '}
                            <span className="text-amber-400 font-bold">{evt.new_role}</span>
                          </div>
                        )}
                      </div>

                      {evt.message && (
                        <div className="rounded bg-slate-900 p-2 text-slate-300 font-mono text-[11px] break-all border border-slate-850">
                          <span className="text-slate-500 font-sans">Message: </span>
                          {evt.message}
                        </div>
                      )}

                      {evt.has_redacted_secret && (
                        <div className="text-[10px] text-rose-300 font-medium">
                          [TG005 Sanitized: Potential credential/secret token masked prior to display]
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 'playbook' && (
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                    Recommended Tier-1 Triage Workflow:
                  </h4>
                  <ol className="space-y-2.5 text-xs text-slate-300">
                    {finding.suggested_investigation_steps.map((step, sIdx) => (
                      <li
                        key={sIdx}
                        className="flex items-start gap-2.5 rounded border border-slate-800 bg-slate-950/60 p-3"
                      >
                        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-teal-950 border border-teal-800 font-mono text-[10px] text-teal-300 font-bold">
                          {sIdx + 1}
                        </span>
                        <span className="leading-relaxed">{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              )}

              {activeTab === 'raw_json' && (
                <div className="rounded border border-slate-800 bg-slate-950 p-3">
                  <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-96">
                    {JSON.stringify(finding, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Drawer Footer */}
        <div className="border-t border-slate-800 px-6 py-3 bg-slate-950/60 flex items-center justify-between text-xs text-slate-400">
          <span>All values rendered as escaped text</span>
          <button
            onClick={onClose}
            className="rounded bg-slate-800 hover:bg-slate-700 px-3 py-1.5 text-slate-200 transition-colors cursor-pointer font-medium"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
