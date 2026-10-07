import { AlertCircle, BookOpen, CheckCircle, Shield } from 'lucide-react';
import React from 'react';
import { RULE_DEFINITIONS } from '../engine/rules';

export const RulesGuide: React.FC = () => {
  return (
    <div className="mx-auto max-w-5xl py-8 px-4 sm:px-6 space-y-6">
      <div className="space-y-2">
        <div className="inline-flex items-center gap-2 text-xs font-semibold text-teal-400">
          <BookOpen className="h-4 w-4" />
          <span>SOC Behavioral Heuristics</span>
        </div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          Detection Rule Inventory & Playbooks
        </h1>
        <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
          TraceGuard enforces five deterministic behavioral rules designed to detect credential sprays, account takeovers, unauthorized privilege escalation, egress anomalies, and sensitive credential exposure.
        </p>
      </div>

      <div className="space-y-6 pt-2">
        {Object.values(RULE_DEFINITIONS).map((rule) => {
          return (
            <div
              key={rule.id}
              className="rounded-lg border border-slate-800 bg-slate-900/60 p-6 space-y-4"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-base font-bold text-teal-400">
                    {rule.id}
                  </span>
                  <span className="text-slate-600">·</span>
                  <h2 className="text-base font-semibold text-slate-100">
                    {rule.name}
                  </h2>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">{rule.category}</span>
                  <span
                    className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                      rule.severity === 'critical'
                        ? 'text-rose-400 bg-rose-950/80 border border-rose-800'
                        : rule.severity === 'high'
                        ? 'text-amber-400 bg-amber-950/80 border border-amber-800'
                        : 'text-yellow-400 bg-yellow-950/80 border border-yellow-800'
                    }`}
                  >
                    {rule.severity}
                  </span>
                </div>
              </div>

              {/* Threshold Specification */}
              <div className="rounded border border-slate-800 bg-slate-950/80 p-3 text-xs">
                <span className="text-slate-500 font-medium uppercase text-[10px] block mb-1">
                  Threshold & Logic Specification
                </span>
                <span className="font-mono text-slate-200">{rule.threshold_summary}</span>
              </div>

              {/* Rationale and Legitimate Causes */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="space-y-1">
                  <span className="font-semibold text-slate-300">Security Threat Context</span>
                  <p className="text-slate-400 leading-relaxed">{rule.rationale}</p>
                </div>
                <div className="space-y-1">
                  <span className="font-semibold text-teal-300">Legitimate Possible Causes</span>
                  <p className="text-slate-400 leading-relaxed">{rule.legitimate_causes}</p>
                </div>
              </div>

              {/* Investigation Playbook */}
              <div className="space-y-2 pt-2 border-t border-slate-850">
                <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
                  Recommended Tier-1 Investigation Playbook:
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  {rule.investigation_steps.map((step, idx) => (
                    <div
                      key={idx}
                      className="rounded border border-slate-800/80 bg-slate-950/40 p-2.5 flex items-start gap-2"
                    >
                      <span className="font-mono text-[10px] text-teal-400 font-bold mt-0.5">
                        {idx + 1}.
                      </span>
                      <span className="text-slate-300 leading-relaxed">{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
