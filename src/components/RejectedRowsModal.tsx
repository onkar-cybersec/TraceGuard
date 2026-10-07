import { AlertTriangle, X } from 'lucide-react';
import React from 'react';
import { RejectedRow } from '../engine/types';

interface RejectedRowsModalProps {
  rejectedRows: RejectedRow[];
  totalRejected: number;
  isOpen: boolean;
  onClose: () => void;
}

export const RejectedRowsModal: React.FC<RejectedRowsModalProps> = ({
  rejectedRows,
  totalRejected,
  isOpen,
  onClose,
}) => {
  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-3xl max-h-[85vh] rounded-lg border border-amber-900/60 bg-slate-900 shadow-2xl flex flex-col overflow-hidden text-slate-100"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="border-b border-slate-800 px-6 py-4 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-400" />
            <div>
              <h3 className="text-sm font-bold text-slate-100">
                Rejected Log Rows ({totalRejected.toLocaleString()})
              </h3>
              <p className="text-xs text-slate-400">
                These rows failed strict schema validation and were excluded from correlation.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Table Content */}
        <div className="flex-1 overflow-y-auto p-6">
          <div className="rounded border border-slate-800 overflow-hidden">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <th className="py-2.5 px-3 w-16">Row #</th>
                  <th className="py-2.5 px-3 w-64">Validation Error</th>
                  <th className="py-2.5 px-3">Raw Content Excerpt</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 bg-slate-900/80">
                {rejectedRows.map((r) => (
                  <tr key={r.row_number} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-3 font-mono font-semibold text-amber-400">
                      {r.row_number}
                    </td>
                    <td className="py-2.5 px-3 text-rose-300 font-medium">
                      {r.error}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-400 break-all text-[11px]">
                      {r.raw_content}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-slate-800 px-6 py-3 bg-slate-950/60 flex items-center justify-between text-xs text-slate-400">
          <span>Valid rows were still analyzed normally</span>
          <button
            onClick={onClose}
            className="rounded bg-slate-800 hover:bg-slate-700 px-4 py-1.5 text-slate-200 transition-colors cursor-pointer font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
