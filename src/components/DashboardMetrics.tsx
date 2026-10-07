import { AlertTriangle, CheckCircle2, FileText, Filter, ShieldAlert } from 'lucide-react';
import React from 'react';
import { DetectionFinding, ValidationSummary } from '../engine/types';

interface DashboardMetricsProps {
  validation: ValidationSummary;
  totalFindings: number;
  filteredFindingsCount: number;
  filteredFindings: DetectionFinding[];
  globalFindings: DetectionFinding[];
  isFiltered: boolean;
  onOpenRejectedModal: () => void;
}

export const DashboardMetrics: React.FC<DashboardMetricsProps> = ({
  validation,
  totalFindings,
  filteredFindingsCount,
  filteredFindings,
  globalFindings,
  isFiltered,
  onOpenRejectedModal,
}) => {
  // Severity counts strictly driven by filtered findings
  const criticalCount = filteredFindings.filter((f) => f.severity === 'critical').length;
  const highCount = filteredFindings.filter((f) => f.severity === 'high').length;
  const mediumCount = filteredFindings.filter((f) => f.severity === 'medium').length;
  const lowCount = filteredFindings.filter((f) => f.severity === 'low').length;

  // Global totals for comparison
  const globalCrit = globalFindings.filter((f) => f.severity === 'critical').length;
  const globalHigh = globalFindings.filter((f) => f.severity === 'high').length;
  const globalMed = globalFindings.filter((f) => f.severity === 'medium').length;

  return (
    <div className="space-y-3">
      {/* Primary KPI Grid: Explicitly separate Global Source metrics from Findings */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4">
        {/* Total Analyzed (Global Source) */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Analyzed</span>
            <FileText className="h-4 w-4 text-slate-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono tracking-tight text-slate-100 tabular-nums">
              {validation.total_rows.toLocaleString()}
            </span>
            <span className="text-xs text-slate-500">records</span>
          </div>
          <div className="mt-1 text-[11px] text-slate-500 truncate" title={validation.file_name}>
            Global source · {validation.file_name}
          </div>
        </div>

        {/* Valid Events (Global Source) */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Valid Events</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono tracking-tight text-emerald-400 tabular-nums">
              {validation.valid_count.toLocaleString()}
            </span>
            <span className="text-xs text-slate-500">
              {validation.total_rows > 0
                ? `${Math.round((validation.valid_count / validation.total_rows) * 100)}%`
                : '0%'}
            </span>
          </div>
          <div className="mt-1 text-[11px] text-slate-500">
            Global validated events
          </div>
        </div>

        {/* Rejected Rows (Global Source) */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Rejected Rows</span>
            <AlertTriangle
              className={`h-4 w-4 ${validation.rejected_count > 0 ? 'text-amber-400' : 'text-slate-500'}`}
            />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className={`text-2xl font-bold font-mono tracking-tight tabular-nums ${
                validation.rejected_count > 0 ? 'text-amber-400' : 'text-slate-400'
              }`}
            >
              {validation.rejected_count.toLocaleString()}
            </span>
            {validation.rejected_count > 0 && (
              <button
                onClick={onOpenRejectedModal}
                className="text-xs text-amber-400 hover:text-amber-300 underline underline-offset-2 cursor-pointer font-medium"
              >
                Inspect &rarr;
              </button>
            )}
          </div>
          <div className="mt-1 text-[11px] text-slate-500">
            {validation.rejected_count > 0
              ? 'Global schema exclusions'
              : 'Zero validation errors'}
          </div>
        </div>

        {/* Correlated Findings (Driven by Filters) */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">
              {isFiltered ? 'Filtered Findings' : 'Correlated Findings'}
            </span>
            <ShieldAlert
              className={`h-4 w-4 ${filteredFindingsCount > 0 ? 'text-rose-400' : 'text-emerald-400'}`}
            />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className={`text-2xl font-bold font-mono tracking-tight tabular-nums ${
                filteredFindingsCount > 0 ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {filteredFindingsCount}
            </span>
            {isFiltered && (
              <span className="text-xs text-slate-400 font-mono">
                of {totalFindings} total
              </span>
            )}
          </div>
          <div className="mt-1 flex items-center gap-1.5 text-[11px] text-slate-400 flex-wrap">
            <span>Critical: <strong className="text-rose-400 font-mono">{criticalCount}</strong>{isFiltered && <span className="text-slate-500 font-mono text-[10px]">/{globalCrit}</span>}</span>
            <span>·</span>
            <span>High: <strong className="text-orange-400 font-mono">{highCount}</strong>{isFiltered && <span className="text-slate-500 font-mono text-[10px]">/{globalHigh}</span>}</span>
            <span>·</span>
            <span>Med: <strong className="text-amber-400 font-mono">{mediumCount}</strong>{isFiltered && <span className="text-slate-500 font-mono text-[10px]">/{globalMed}</span>}</span>
          </div>
        </div>
      </div>

      {/* Global vs Filtered Indicator Bar if Active */}
      {isFiltered && (
        <div className="flex items-center justify-between rounded border border-teal-900/40 bg-teal-950/20 px-3 py-1.5 text-xs text-teal-300">
          <div className="flex items-center gap-2">
            <Filter className="h-3.5 w-3.5 text-teal-400" />
            <span>
              Showing <strong className="font-mono text-slate-100">{filteredFindingsCount}</strong> of{' '}
              <strong className="font-mono text-slate-100">{totalFindings}</strong> total findings. Severity breakdown and panels below reflect active filters. Source events remain global.
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
