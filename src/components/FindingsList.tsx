import { ChevronRight, Filter, Info, Search, ShieldAlert, X } from 'lucide-react';
import React from 'react';
import { DetectionCategory, DetectionFinding, Severity } from '../engine/types';

interface FindingsListProps {
  findings: DetectionFinding[];
  allFindingsCount: number;
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  selectedRule: string | null;
  setSelectedRule: (rule: string | null) => void;
  selectedSeverity: Severity | null;
  setSelectedSeverity: (sev: Severity | null) => void;
  selectedCategory: DetectionCategory | null;
  setSelectedCategory: (cat: DetectionCategory | null) => void;
  onInspectFinding: (finding: DetectionFinding) => void;
}

const RULES_LIST = [
  { id: 'TG001', label: 'TG001: Auth Burst' },
  { id: 'TG002', label: 'TG002: Compromise' },
  { id: 'TG003', label: 'TG003: Admin Role' },
  { id: 'TG004', label: 'TG004: Egress' },
  { id: 'TG005', label: 'TG005: Secret Leak' },
];

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export const FindingsList: React.FC<FindingsListProps> = ({
  findings,
  allFindingsCount,
  searchQuery,
  setSearchQuery,
  selectedRule,
  setSelectedRule,
  selectedSeverity,
  setSelectedSeverity,
  selectedCategory,
  setSelectedCategory,
  onInspectFinding,
}) => {
  const hasActiveFilters = Boolean(searchQuery || selectedRule || selectedSeverity || selectedCategory);

  const clearAllFilters = () => {
    setSearchQuery('');
    setSelectedRule(null);
    setSelectedSeverity(null);
    setSelectedCategory(null);
  };

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 sm:p-5 space-y-4">
      {/* Header and Toolbar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-teal-400" />
            Correlated Security Findings
            <span className="text-xs font-mono text-slate-500 font-normal">
              ({findings.length} of {allFindingsCount})
            </span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Deterministic rule triggers requiring Tier-1 human analyst validation.
          </p>
        </div>

        {/* Search Input */}
        <div className="relative w-full md:w-72">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search IP, user, rule, or summary..."
            className="w-full rounded border border-slate-700 bg-slate-950 pl-9 pr-8 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-2.5 top-2.5 text-slate-500 hover:text-slate-300 cursor-pointer"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Filter Segmented Controls */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-b border-slate-800/80 py-2.5">
        {/* Rule Filter Buttons */}
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-[11px] font-medium text-slate-400 mr-1 flex items-center gap-1">
            <Filter className="h-3 w-3 text-slate-500" /> Rule:
          </span>
          <button
            onClick={() => setSelectedRule(null)}
            className={`px-2.5 py-1 text-xs rounded transition-colors cursor-pointer font-medium ${
              selectedRule === null
                ? 'bg-teal-900/60 text-teal-200 border border-teal-700/60'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            All
          </button>
          {RULES_LIST.map((r) => (
            <button
              key={r.id}
              onClick={() => setSelectedRule(selectedRule === r.id ? null : r.id)}
              className={`px-2.5 py-1 text-xs rounded transition-colors cursor-pointer font-mono ${
                selectedRule === r.id
                  ? 'bg-teal-900/60 text-teal-200 border border-teal-700/60'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              {r.id}
            </button>
          ))}
        </div>

        {/* Severity Tabs */}
        <div className="flex items-center gap-1">
          <span className="text-[11px] font-medium text-slate-400 mr-1">Severity:</span>
          <button
            onClick={() => setSelectedSeverity(null)}
            className={`px-2 py-0.5 text-xs rounded transition-colors cursor-pointer ${
              selectedSeverity === null
                ? 'bg-slate-800 text-slate-100 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All
          </button>
          {SEVERITIES.map((sev) => {
            const isSel = selectedSeverity === sev;
            return (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(isSel ? null : sev)}
                className={`px-2 py-0.5 text-xs rounded transition-colors cursor-pointer capitalize ${
                  isSel
                    ? sev === 'critical'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : sev === 'high'
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : sev === 'medium'
                      ? 'bg-yellow-950 text-yellow-300 border border-yellow-800'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            );
          })}
        </div>

        {/* Clear Filters */}
        {hasActiveFilters && (
          <button
            onClick={clearAllFilters}
            className="text-xs text-teal-400 hover:text-teal-300 underline underline-offset-2 cursor-pointer flex items-center gap-1"
          >
            <X className="h-3 w-3" />
            Reset Filters
          </button>
        )}
      </div>

      {/* Findings List Items */}
      {findings.length === 0 ? (
        <div className="rounded-lg border border-slate-800/80 bg-slate-950/40 p-8 text-center space-y-3">
          {hasActiveFilters ? (
            <>
              <p className="text-sm text-slate-300">No findings match the current filter criteria.</p>
              <button
                onClick={clearAllFilters}
                className="text-xs text-teal-400 hover:text-teal-300 underline cursor-pointer"
              >
                Clear all active filters to view all {allFindingsCount} findings
              </button>
            </>
          ) : (
            <>
              <div className="inline-flex h-10 w-10 items-center justify-center rounded-full bg-emerald-950/60 text-emerald-400">
                <Info className="h-5 w-5" />
              </div>
              <h4 className="text-sm font-semibold text-slate-200">Zero Rule Violations Identified</h4>
              <p className="max-w-md mx-auto text-xs text-slate-400 leading-relaxed">
                No events in this dataset met the configured thresholds for TG001–TG005.
              </p>
              <div className="max-w-md mx-auto rounded border border-slate-800 bg-slate-900/50 p-2.5 text-[11px] text-slate-400 text-left">
                <strong className="text-slate-300">Important SOC Note:</strong> The absence of findings indicates that baseline rules were not tripped; it does not constitute mathematical proof that the system is fully secure or devoid of low-and-slow anomalies.
              </div>
            </>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {findings.map((finding) => {
            const isCritical = finding.severity === 'critical';
            const isHigh = finding.severity === 'high';
            const isMedium = finding.severity === 'medium';

            const severityBorder = isCritical
              ? 'border-rose-900/50 hover:border-rose-700/70'
              : isHigh
              ? 'border-amber-900/50 hover:border-amber-700/70'
              : isMedium
              ? 'border-yellow-900/50 hover:border-yellow-700/70'
              : 'border-slate-800 hover:border-slate-700';

            const severityBadgeStyle = isCritical
              ? 'text-rose-400 bg-rose-950/60 border border-rose-800/60'
              : isHigh
              ? 'text-orange-400 bg-orange-950/60 border border-orange-800/60'
              : isMedium
              ? 'text-yellow-400 bg-yellow-950/60 border border-yellow-800/60'
              : 'text-emerald-400 bg-emerald-950/60 border border-emerald-800/60';

            return (
              <div
                key={finding.id}
                className={`rounded-lg border bg-slate-950/50 p-4 transition-all ${severityBorder}`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${severityBadgeStyle}`}>
                      {finding.severity}
                    </span>
                    <span className="font-mono text-xs font-semibold text-teal-400">
                      {finding.rule_id}
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className="text-xs text-slate-300 font-medium">
                      {finding.rule_title}
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className="text-xs text-slate-400">
                      {finding.category}
                    </span>
                  </div>

                  <span className="font-mono text-[11px] text-slate-500">
                    {finding.id}
                  </span>
                </div>

                <div className="mt-3">
                  <h4 className="text-sm font-semibold text-slate-100 leading-snug">
                    {finding.summary}
                  </h4>
                  <p className="mt-1 text-xs text-slate-400 line-clamp-2 leading-relaxed">
                    {finding.explanation}
                  </p>
                </div>

                {/* Entity & Time Metadata (Unboxed text with separators per Zero-Pill rule) */}
                <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-400">
                  {finding.entity_user && (
                    <>
                      <span>User: <strong className="text-slate-200">{finding.entity_user}</strong></span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                    </>
                  )}
                  {finding.entity_source_ip && (
                    <>
                      <span>Source IP: <code className="text-slate-300 font-mono">{finding.entity_source_ip}</code></span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                    </>
                  )}
                  <span>Time: <span className="font-mono text-slate-400">{finding.first_seen_utc.slice(11, 19)} &rarr; {finding.last_seen_utc.slice(11, 19)} UTC</span></span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="font-mono text-teal-400">{finding.supporting_events.length} supporting events</span>
                </div>

                {/* Action button */}
                <div className="mt-3 pt-3 border-t border-slate-900 flex items-center justify-between">
                  <span className="text-[11px] text-slate-500 italic truncate max-w-md">
                    {finding.caveat_notice.slice(0, 90)}...
                  </span>
                  <button
                    onClick={() => onInspectFinding(finding)}
                    className="flex items-center gap-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700/80 px-3 py-1.5 text-xs font-semibold text-teal-300 hover:text-teal-200 transition-colors cursor-pointer shrink-0"
                  >
                    <span>Inspect Evidence</span>
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
