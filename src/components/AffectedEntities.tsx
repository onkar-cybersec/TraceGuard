import { Globe, UserCheck } from 'lucide-react';
import React, { useMemo } from 'react';
import { DetectionFinding } from '../engine/types';

interface AffectedEntitiesProps {
  findings: DetectionFinding[];
  globalTotalCount?: number;
  isFiltered?: boolean;
  activeSearch: string;
  onSelectEntitySearch: (query: string) => void;
}

export const AffectedEntities: React.FC<AffectedEntitiesProps> = ({
  findings,
  globalTotalCount,
  isFiltered = false,
  activeSearch,
  onSelectEntitySearch,
}) => {
  // Aggregate top source IPs strictly from current (filtered) findings
  const topIps = useMemo(() => {
    const counts = new Map<string, number>();
    findings.forEach((f) => {
      if (f.entity_source_ip) {
        counts.set(f.entity_source_ip, (counts.get(f.entity_source_ip) || 0) + 1);
      }
    });
    return Array.from(counts.entries())
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [findings]);

  // Aggregate top users
  const topUsers = useMemo(() => {
    const counts = new Map<string, number>();
    findings.forEach((f) => {
      if (f.entity_user) {
        counts.set(f.entity_user, (counts.get(f.entity_user) || 0) + 1);
      }
    });
    return Array.from(counts.entries())
      .map(([user, count]) => ({ user, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [findings]);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Top Source IPs */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-teal-400" />
            <h3 className="text-sm font-semibold text-slate-200">Flagged Source IPs</h3>
          </div>
          <span className="text-[11px] font-mono text-slate-500">{topIps.length} active</span>
        </div>

        {topIps.length === 0 ? (
          <div className="text-xs text-slate-500 py-3 text-center">No source IPs correlated</div>
        ) : (
          <div className="space-y-1.5">
            {topIps.map(({ ip, count }) => {
              const isSelected = activeSearch.includes(ip);
              return (
                <button
                  key={ip}
                  onClick={() => onSelectEntitySearch(isSelected ? '' : ip)}
                  className={`w-full flex items-center justify-between rounded px-2.5 py-1.5 text-xs transition-colors cursor-pointer ${
                    isSelected
                      ? 'bg-teal-950/40 border border-teal-850 text-teal-300'
                      : 'hover:bg-slate-800/60 text-slate-300'
                  }`}
                >
                  <span className="font-mono">{ip}</span>
                  <span className="font-mono text-slate-400">
                    {count} {count === 1 ? 'finding' : 'findings'}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Top Impacted Users */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <UserCheck className="h-4 w-4 text-teal-400" />
            <h3 className="text-sm font-semibold text-slate-200">Impacted Accounts</h3>
          </div>
          <span className="text-[11px] font-mono text-slate-500">{topUsers.length} active</span>
        </div>

        {topUsers.length === 0 ? (
          <div className="text-xs text-slate-500 py-3 text-center">No accounts correlated</div>
        ) : (
          <div className="space-y-1.5">
            {topUsers.map(({ user, count }) => {
              const isSelected = activeSearch.includes(user);
              return (
                <button
                  key={user}
                  onClick={() => onSelectEntitySearch(isSelected ? '' : user)}
                  className={`w-full flex items-center justify-between rounded px-2.5 py-1.5 text-xs transition-colors cursor-pointer ${
                    isSelected
                      ? 'bg-teal-950/40 border border-teal-850 text-teal-300'
                      : 'hover:bg-slate-800/60 text-slate-300'
                  }`}
                >
                  <span className="font-medium">{user}</span>
                  <span className="font-mono text-slate-400">
                    {count} {count === 1 ? 'finding' : 'findings'}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
