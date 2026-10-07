import { AlertTriangle, Cpu, FileCheck, Lock, Shield, Sliders } from 'lucide-react';
import React from 'react';

export const PrivacyView: React.FC = () => {
  return (
    <div className="mx-auto max-w-5xl py-8 px-4 sm:px-6 space-y-6">
      <div className="space-y-2">
        <div className="inline-flex items-center gap-2 text-xs font-semibold text-teal-400">
          <Shield className="h-4 w-4" />
          <span>Security Architecture & Governance</span>
        </div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          TraceGuard Privacy Model & Operational Boundaries
        </h1>
        <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
          TraceGuard was engineered specifically for sensitive security investigations where logs must never be exposed to public cloud LLMs, external APIs, third-party analytics, or remote database services.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 pt-2">
        {/* Local Sandboxing */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <div className="h-8 w-8 rounded-lg bg-teal-950/80 border border-teal-800/60 flex items-center justify-center text-teal-400">
            <Lock className="h-4 w-4" />
          </div>
          <h2 className="text-sm font-bold text-slate-100">100% In-Browser Execution</h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            All log parsing, sliding-window calculations, and report rendering run client-side in your local browser sandbox via JavaScript. Network egress requests for telemetry or processing are zero.
          </p>
        </div>

        {/* Secret Scrubbing */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <div className="h-8 w-8 rounded-lg bg-teal-950/80 border border-teal-800/60 flex items-center justify-center text-teal-400">
            <FileCheck className="h-4 w-4" />
          </div>
          <h2 className="text-sm font-bold text-slate-100">Pre-Display Secret Scrubbing</h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            Rule TG005 actively scrubs AWS access keys, private key headers, Bearer tokens, and password strings before logs are rendered to the DOM or included in exports.
          </p>
        </div>

        {/* Deterministic Auditing */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <div className="h-8 w-8 rounded-lg bg-teal-950/80 border border-teal-800/60 flex items-center justify-center text-teal-400">
            <Cpu className="h-4 w-4" />
          </div>
          <h2 className="text-sm font-bold text-slate-100">Deterministic Logic</h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            No probabilistic hallucination or black-box model guessing. Correlation findings are strictly reproducible, inspectable, and reference precise event IDs and timestamps.
          </p>
        </div>
      </div>

      {/* Mandatory Limitations Callout */}
      <div className="rounded-lg border border-amber-900/40 bg-amber-950/10 p-5 space-y-2.5">
        <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          Mandatory SOC Investigation Caveats
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          <strong>Absence of Findings is Not Proof of Security:</strong> A log dataset that yields zero findings merely indicates that the 5 specified heuristic thresholds were not crossed. An adversary utilizing low-frequency credential attacks (e.g., 2 attempts per hour), legitimate compromised credentials, or unmonitored communication channels will not trigger these specific rules.
        </p>
        <p className="text-xs text-slate-300 leading-relaxed">
          <strong>Indicators Require Human Triage:</strong> Findings are behavioral flags. For example, a 15 MiB egress transfer may represent an authorized database snapshot or software package download; an admin role grant may represent an approved ITSM change request. Always verify indicators against authorized enterprise tickets.
        </p>
      </div>
    </div>
  );
};
