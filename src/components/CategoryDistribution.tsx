import { Layers } from 'lucide-react';
import React from 'react';
import { DetectionCategory, DetectionFinding } from '../engine/types';

interface CategoryDistributionProps {
  findings: DetectionFinding[];
  globalTotalCount?: number;
  isFiltered?: boolean;
  activeCategoryFilter: string | null;
  onSelectCategory: (category: DetectionCategory | null) => void;
}

const ALL_CATEGORIES: DetectionCategory[] = [
  'Credential Attack',
  'Account Compromise',
  'Privilege Escalation',
  'Suspicious Network Transfer',
  'Secret Exposure',
];

export const CategoryDistribution: React.FC<CategoryDistributionProps> = ({
  findings,
  globalTotalCount,
  isFiltered = false,
  activeCategoryFilter,
  onSelectCategory,
}) => {
  const total = findings.length;

  const categoryCounts = ALL_CATEGORIES.map((cat) => {
    const count = findings.filter((f) => f.category === cat).length;
    const percent = total > 0 ? Math.round((count / total) * 100) : 0;
    return { category: cat, count, percent };
  });

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 sm:p-5 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-teal-400" />
          <h3 className="text-sm font-semibold text-slate-200">Detection Categories</h3>
          {isFiltered && globalTotalCount !== undefined && (
            <span className="text-[11px] font-mono text-teal-400">
              ({findings.length} filtered of {globalTotalCount})
            </span>
          )}
        </div>
        {activeCategoryFilter && (
          <button
            onClick={() => onSelectCategory(null)}
            className="text-[11px] text-teal-400 hover:text-teal-300 underline cursor-pointer"
          >
            Clear category filter
          </button>
        )}
      </div>

      <div className="space-y-2 pt-1">
        {categoryCounts.map(({ category, count, percent }) => {
          const isSelected = activeCategoryFilter === category;
          return (
            <button
              key={category}
              onClick={() => onSelectCategory(isSelected ? null : category)}
              className={`w-full text-left rounded p-1.5 transition-colors cursor-pointer group ${
                isSelected
                  ? 'bg-teal-950/40 border border-teal-800/60'
                  : 'hover:bg-slate-800/40'
              }`}
            >
              <div className="flex items-center justify-between text-xs mb-1">
                <span className={`font-medium ${isSelected ? 'text-teal-300' : 'text-slate-300'}`}>
                  {category}
                </span>
                <span className="font-mono text-slate-400 tabular-nums">
                  {count} <span className="text-[10px] text-slate-500">({percent}%)</span>
                </span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                <div
                  style={{ width: `${percent}%` }}
                  className={`h-full transition-all duration-300 ${
                    isSelected ? 'bg-teal-400' : 'bg-teal-600/70 group-hover:bg-teal-500'
                  }`}
                />
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};
