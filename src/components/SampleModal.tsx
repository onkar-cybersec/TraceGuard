import { Download, FileCode, FileSpreadsheet, X } from 'lucide-react';
import React from 'react';
import { BENIGN_DEMO_CSV, BENIGN_DEMO_JSON, TRIGGER_DEMO_CSV, TRIGGER_DEMO_JSON } from '../data/samples';

interface SampleModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoadDirect: (content: string, fileName: string, fileSize: number) => void;
}

export const SampleModal: React.FC<SampleModalProps> = ({
  isOpen,
  onClose,
  onLoadDirect,
}) => {
  if (!isOpen) return null;

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
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl rounded-lg border border-slate-800 bg-slate-900 shadow-2xl flex flex-col overflow-hidden text-slate-100"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="border-b border-slate-800 px-6 py-4 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2">
            <Download className="h-4 w-4 text-teal-400" />
            <h3 className="text-sm font-bold text-slate-100">
              Download Synthetic Test Datasets
            </h3>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="p-6 space-y-4 text-xs">
          <p className="text-slate-400 leading-relaxed">
            All datasets are synthetically generated for benchmark verification. They use RFC documentation IPs (198.51.100.0/24, 203.0.113.0/24) and fake dummy secrets.
          </p>

          <div className="space-y-3">
            {/* Trigger Dataset Card */}
            <div className="rounded border border-amber-900/40 bg-slate-950/40 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-amber-300">
                  Full Indicator Test Set (TG001–TG005)
                </span>
                <span className="text-[10px] font-mono text-slate-500">20 events</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Contains auth failures, compromise success, admin role change, 18 MiB egress & port 4444, plus fake secrets.
              </p>
              <div className="flex items-center gap-2 pt-1">
                <button
                  onClick={() => downloadFile(TRIGGER_DEMO_JSON, 'traceguard_trigger_sample.json', 'application/json')}
                  className="flex-1 flex items-center justify-center gap-1.5 rounded border border-slate-700 bg-slate-900 py-1.5 px-2 hover:bg-slate-800 text-slate-200 transition-colors cursor-pointer"
                >
                  <FileCode className="h-3.5 w-3.5 text-teal-400" />
                  <span>Download JSON</span>
                </button>
                <button
                  onClick={() => downloadFile(TRIGGER_DEMO_CSV, 'traceguard_trigger_sample.csv', 'text/csv')}
                  className="flex-1 flex items-center justify-center gap-1.5 rounded border border-slate-700 bg-slate-900 py-1.5 px-2 hover:bg-slate-800 text-slate-200 transition-colors cursor-pointer"
                >
                  <FileSpreadsheet className="h-3.5 w-3.5 text-teal-400" />
                  <span>Download CSV</span>
                </button>
                <button
                  onClick={() => {
                    onLoadDirect(TRIGGER_DEMO_JSON, 'traceguard_trigger_sample.json', TRIGGER_DEMO_JSON.length);
                    onClose();
                  }}
                  className="rounded bg-teal-600 hover:bg-teal-500 text-slate-950 font-semibold py-1.5 px-3 transition-colors cursor-pointer"
                >
                  Load in App
                </button>
              </div>
            </div>

            {/* Benign Baseline Card */}
            <div className="rounded border border-emerald-900/40 bg-slate-950/40 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-emerald-300">
                  Benign Enterprise Baseline (Zero Findings)
                </span>
                <span className="text-[10px] font-mono text-slate-500">7 events</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Standard corporate operations with regular logins, internal transfers, and non-privileged role changes.
              </p>
              <div className="flex items-center gap-2 pt-1">
                <button
                  onClick={() => downloadFile(BENIGN_DEMO_JSON, 'traceguard_benign_sample.json', 'application/json')}
                  className="flex-1 flex items-center justify-center gap-1.5 rounded border border-slate-700 bg-slate-900 py-1.5 px-2 hover:bg-slate-800 text-slate-200 transition-colors cursor-pointer"
                >
                  <FileCode className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Download JSON</span>
                </button>
                <button
                  onClick={() => downloadFile(BENIGN_DEMO_CSV, 'traceguard_benign_sample.csv', 'text/csv')}
                  className="flex-1 flex items-center justify-center gap-1.5 rounded border border-slate-700 bg-slate-900 py-1.5 px-2 hover:bg-slate-800 text-slate-200 transition-colors cursor-pointer"
                >
                  <FileSpreadsheet className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Download CSV</span>
                </button>
                <button
                  onClick={() => {
                    onLoadDirect(BENIGN_DEMO_JSON, 'traceguard_benign_sample.json', BENIGN_DEMO_JSON.length);
                    onClose();
                  }}
                  className="rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold py-1.5 px-3 transition-colors cursor-pointer"
                >
                  Load in App
                </button>
              </div>
            </div>
          </div>
        </div>

        <div className="border-t border-slate-800 px-6 py-3 bg-slate-950/60 flex justify-end">
          <button
            onClick={onClose}
            className="rounded bg-slate-800 hover:bg-slate-700 px-4 py-1.5 text-slate-200 transition-colors cursor-pointer font-medium text-xs"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
