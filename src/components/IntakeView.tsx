import { AlertCircle, CheckCircle2, Download, FileCode, FileSpreadsheet, FileText, Info, Lock, Play, ShieldAlert, Upload } from 'lucide-react';
import React, { useRef, useState } from 'react';
import { BENIGN_DEMO_CSV, BENIGN_DEMO_JSON, TRIGGER_DEMO_CSV, TRIGGER_DEMO_JSON } from '../data/samples';

interface IntakeViewProps {
  onLoadLogContent: (content: string, fileName: string, fileSize: number) => void;
  onOpenSchemaHelp: () => void;
  fatalError?: string;
}

export const IntakeView: React.FC<IntakeViewProps> = ({
  onLoadLogContent,
  onOpenSchemaHelp,
  fatalError,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [dragError, setDragError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = (file: File) => {
    setDragError(null);
    if (!file) return;

    if (file.size > 2 * 1024 * 1024) {
      setDragError(`File exceeds 2 MiB safety limit (${(file.size / (1024 * 1024)).toFixed(2)} MiB). Please upload a smaller log excerpt.`);
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      onLoadLogContent(text, file.name, file.size);
    };
    reader.onerror = () => {
      setDragError('Failed to read file contents from browser storage.');
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const downloadFile = (content: string, filename: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="mx-auto max-w-5xl py-8 px-4 sm:px-6 space-y-8">
      {/* Hero section */}
      <div className="space-y-3 text-center sm:text-left">
        <div className="inline-flex items-center gap-2 rounded border border-teal-800/40 bg-teal-950/30 px-3 py-1 text-xs font-medium text-teal-300">
          <Lock className="h-3.5 w-3.5 text-teal-400" />
          <span>100% Client-Side Engine · Zero Remote Ingestion</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100">
          Deterministic Security Log Investigation & Triage
        </h1>
        <p className="max-w-3xl text-sm sm:text-base text-slate-400 leading-relaxed">
          TraceGuard correlates structured authentication, role, egress, and error logs against strict SOC behavioral heuristics (TG001–TG005). All processing, secret sanitization, and report generation execute entirely in your local browser sandbox.
        </p>
      </div>

      {/* Fatal or Drag Error Banner */}
      {(fatalError || dragError) && (
        <div className="rounded-lg border border-rose-900/60 bg-rose-950/30 p-4 text-rose-200 flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1 text-sm">
            <div className="font-semibold text-rose-300">Parsing Failure</div>
            <div>{fatalError || dragError}</div>
          </div>
        </div>
      )}

      {/* Main Action Grid: Upload & Demo Launchers */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Upload Zone */}
        <div className="lg:col-span-7 flex flex-col justify-between rounded-lg border border-slate-800 bg-slate-900/60 p-6">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
                <Upload className="h-4 w-4 text-teal-400" />
                Upload Structured Logs
              </h2>
              <button
                onClick={onOpenSchemaHelp}
                className="text-xs text-teal-400 hover:text-teal-300 underline underline-offset-4 cursor-pointer"
              >
                Schema Help & Aliases
              </button>
            </div>

            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-8 text-center transition-colors cursor-pointer ${
                isDragging
                  ? 'border-teal-500 bg-teal-950/20'
                  : 'border-slate-700 bg-slate-950/40 hover:border-slate-600 hover:bg-slate-950/60'
              }`}
            >
              <FileSpreadsheet className="h-10 w-10 text-slate-500 mb-3" />
              <div className="text-sm font-medium text-slate-300">
                Drag and drop a log file here, or <span className="text-teal-400">browse files</span>
              </div>
              <div className="mt-1 text-xs text-slate-500">
                Accepts <code className="text-slate-400">.json</code> (array or <code className="text-slate-400">{'{events:[]}'}</code>) or <code className="text-slate-400">.csv</code> (RFC 4180)
              </div>
              <div className="mt-3 flex items-center gap-3 text-[11px] text-slate-500 font-mono">
                <span>Max size: 2 MiB</span>
                <span>·</span>
                <span>Max rows: 20,000 events</span>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,.csv,text/csv,application/json,text/plain"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files.length > 0) {
                    handleFile(e.target.files[0]);
                  }
                }}
              />
            </div>
          </div>

          <div className="mt-6 border-t border-slate-800/80 pt-4 flex flex-wrap items-center justify-between text-xs text-slate-400 gap-2">
            <span className="flex items-center gap-1.5 text-slate-400">
              <CheckCircle2 className="h-3.5 w-3.5 text-teal-400" />
              Automatic secret redaction applied prior to display
            </span>
            <span className="text-slate-500 font-mono">Mixed invalid rows flagged</span>
          </div>
        </div>

        {/* Quick Demo Launchers */}
        <div className="lg:col-span-5 flex flex-col justify-between space-y-4 rounded-lg border border-slate-800 bg-slate-900/60 p-6">
          <div className="space-y-4">
            <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
              <Play className="h-4 w-4 text-teal-400" />
              Instant Benchmark Demos
            </h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              Experience the investigation dashboard immediately with curated synthetic datasets containing benign baseline activity and deterministic indicators.
            </p>

            {/* Trigger Demo Card */}
            <div className="rounded border border-amber-900/30 bg-amber-950/10 p-4 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-amber-300 flex items-center gap-1.5">
                  <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
                  Full Indicator Test Set
                </span>
                <span className="text-[10px] font-mono text-amber-400/80 uppercase">All 5 Rules</span>
              </div>
              <p className="text-xs text-slate-400">
                Contains benign baseline traffic mixed with triggers for TG001 (auth burst), TG002 (compromise), TG003 (admin role), TG004 (10 MiB egress & port 4444), and TG005 (synthetic AWS key/passwords).
              </p>
              <button
                onClick={() => onLoadLogContent(TRIGGER_DEMO_JSON, 'synthetic_trigger_demo.json', TRIGGER_DEMO_JSON.length)}
                className="w-full rounded bg-teal-600 hover:bg-teal-500 text-slate-950 font-semibold py-2 px-3 text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                Launch Trigger Demo (Known Indicators)
              </button>
            </div>

            {/* Benign Baseline Card */}
            <div className="rounded border border-slate-800 bg-slate-950/40 p-4 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                  Benign Enterprise Baseline
                </span>
                <span className="text-[10px] font-mono text-emerald-400/80 uppercase">0 Findings Expected</span>
              </div>
              <p className="text-xs text-slate-400">
                Simulates standard enterprise operations: normal SSO logins, internal cross-subnet 48 MiB replica transfers, and non-privileged role changes.
              </p>
              <button
                onClick={() => onLoadLogContent(BENIGN_DEMO_JSON, 'synthetic_benign_baseline.json', BENIGN_DEMO_JSON.length)}
                className="w-full rounded border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200 font-semibold py-2 px-3 text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer"
              >
                <Play className="h-3.5 w-3.5" />
                Launch Benign Baseline (Zero Findings)
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Synthetic Dataset Downloads & Privacy / Limitations */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
        {/* Downloadable Synthetic Samples */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-5 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <Download className="h-4 w-4 text-teal-400" />
            Download Synthetic Sample Files
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Download local files to test your own ingestion pipelines or examine the CSV/JSON schemas:
          </p>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <button
              onClick={() => downloadFile(TRIGGER_DEMO_JSON, 'traceguard_trigger_sample.json', 'application/json')}
              className="flex items-center justify-center gap-1.5 rounded border border-slate-800 bg-slate-950 p-2 hover:bg-slate-800 text-slate-300 transition-colors cursor-pointer"
            >
              <FileCode className="h-3.5 w-3.5 text-amber-400" />
              <span>Trigger (JSON)</span>
            </button>
            <button
              onClick={() => downloadFile(TRIGGER_DEMO_CSV, 'traceguard_trigger_sample.csv', 'text/csv')}
              className="flex items-center justify-center gap-1.5 rounded border border-slate-800 bg-slate-950 p-2 hover:bg-slate-800 text-slate-300 transition-colors cursor-pointer"
            >
              <FileSpreadsheet className="h-3.5 w-3.5 text-amber-400" />
              <span>Trigger (CSV)</span>
            </button>
            <button
              onClick={() => downloadFile(BENIGN_DEMO_JSON, 'traceguard_benign_sample.json', 'application/json')}
              className="flex items-center justify-center gap-1.5 rounded border border-slate-800 bg-slate-950 p-2 hover:bg-slate-800 text-slate-300 transition-colors cursor-pointer"
            >
              <FileCode className="h-3.5 w-3.5 text-emerald-400" />
              <span>Benign (JSON)</span>
            </button>
            <button
              onClick={() => downloadFile(BENIGN_DEMO_CSV, 'traceguard_benign_sample.csv', 'text/csv')}
              className="flex items-center justify-center gap-1.5 rounded border border-slate-800 bg-slate-950 p-2 hover:bg-slate-800 text-slate-300 transition-colors cursor-pointer"
            >
              <FileSpreadsheet className="h-3.5 w-3.5 text-emerald-400" />
              <span>Benign (CSV)</span>
            </button>
          </div>
        </div>

        {/* Privacy & Operational Boundaries */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-5 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <Info className="h-4 w-4 text-teal-400" />
            Investigative Limitations & Privacy
          </div>
          <ul className="text-xs text-slate-400 space-y-1.5 list-disc pl-4 leading-relaxed">
            <li>
              <strong>Zero External Transmission:</strong> Telemetry, IP addresses, and log contents never leave your device memory.
            </li>
            <li>
              <strong>Indicators, Not Proof:</strong> Rule detections indicate behavioral anomalies that require analyst validation against authorized tickets.
            </li>
            <li>
              <strong>Absence of Findings:</strong> A clean audit report does <em>not</em> guarantee that an environment is free of stealthy unmonitored intrusions.
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};
