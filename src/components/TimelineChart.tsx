import { Calendar, Clock } from 'lucide-react';
import React, { useMemo, useState } from 'react';
import { DetectionFinding, SecurityLogEvent } from '../engine/types';

interface TimelineChartProps {
  events: SecurityLogEvent[];
  findings: DetectionFinding[];
  allFindingsCount?: number;
  isFiltered?: boolean;
}

interface TimeBucket {
  key: string;
  label: string;
  isoStart: string;
  totalCount: number;
  flaggedCount: number;
  normalCount: number;
}

export const TimelineChart: React.FC<TimelineChartProps> = ({
  events,
  findings,
  allFindingsCount = findings.length,
  isFiltered = false,
}) => {
  const [hoveredBucket, setHoveredBucket] = useState<TimeBucket | null>(null);

  // Set of all triggering event IDs strictly driven by current (filtered) findings
  const flaggedEventIds = useMemo(() => {
    const ids = new Set<string>();
    findings.forEach((f) => {
      f.trigger_event_ids.forEach((id) => ids.add(id));
    });
    return ids;
  }, [findings]);

  // Aggregate events into ~12 to 24 time buckets based on span
  const buckets = useMemo(() => {
    if (events.length === 0) return [];

    const minEpoch = events[0].timestamp_epoch;
    const maxEpoch = events[events.length - 1].timestamp_epoch;
    const spanMs = Math.max(maxEpoch - minEpoch, 1000); // at least 1s

    // Choose 12 buckets
    const numBuckets = Math.min(Math.max(Math.floor(events.length / 2), 6), 18);
    const bucketInterval = spanMs / numBuckets;

    const bList: TimeBucket[] = [];
    for (let i = 0; i < numBuckets; i++) {
      const bStart = minEpoch + i * bucketInterval;
      const date = new Date(bStart);
      const timeStr = date.toISOString().slice(11, 16) + 'Z';
      bList.push({
        key: `bucket-${i}`,
        label: timeStr,
        isoStart: date.toISOString(),
        totalCount: 0,
        flaggedCount: 0,
        normalCount: 0,
      });
    }

    events.forEach((evt) => {
      let bIdx = Math.floor((evt.timestamp_epoch - minEpoch) / bucketInterval);
      if (bIdx >= numBuckets) bIdx = numBuckets - 1;
      if (bIdx < 0) bIdx = 0;

      bList[bIdx].totalCount++;
      if (flaggedEventIds.has(evt.id)) {
        bList[bIdx].flaggedCount++;
      } else {
        bList[bIdx].normalCount++;
      }
    });

    return bList;
  }, [events, flaggedEventIds]);

  const maxBucketCount = useMemo(() => {
    if (buckets.length === 0) return 1;
    return Math.max(...buckets.map((b) => b.totalCount), 1);
  }, [buckets]);

  if (events.length === 0) return null;

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 sm:p-5 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Clock className="h-4 w-4 text-teal-400" />
          <h3 className="text-sm font-semibold text-slate-200">UTC Event Timeline</h3>
          <span className="text-xs text-slate-400 font-mono">
            {events[0]?.timestamp.slice(0, 10)}
          </span>
          {isFiltered ? (
            <span className="text-[11px] font-mono text-teal-400 bg-teal-950/60 px-2 py-0.5 rounded border border-teal-800/60">
              Filtered: {findings.length} findings ({flaggedEventIds.size} flagged events)
            </span>
          ) : (
            <span className="text-[11px] font-mono text-slate-400">
              Global: {allFindingsCount} findings ({flaggedEventIds.size} flagged events)
            </span>
          )}
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm bg-teal-500/80 inline-block" />
            <span className="text-slate-400">
              Baseline ({events.length - flaggedEventIds.size} events)
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm bg-rose-500 inline-block" />
            <span className="text-slate-200 font-semibold">
              {isFiltered ? 'Filtered Evidence' : 'Flagged Evidence'} ({flaggedEventIds.size} events)
            </span>
          </div>
        </div>
      </div>

      {/* Axis Bounds Labels */}
      <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 px-1 border-b border-slate-800/60 pb-1">
        <span>Start: {events[0]?.timestamp.slice(11, 19)} UTC</span>
        <span>Peak: {maxBucketCount} events/bucket</span>
        <span>End: {events[events.length - 1]?.timestamp.slice(11, 19)} UTC</span>
      </div>

      {/* SVG Timeline Chart with definite viewBox geometry */}
      <div className="relative pt-1 pb-1">
        <div className="w-full bg-slate-950/60 rounded border border-slate-800/80 p-2 overflow-x-auto">
          <svg
            viewBox="0 0 1000 145"
            className="w-full h-36 min-w-[500px] overflow-visible"
            role="img"
            aria-label="UTC Event Timeline distribution chart"
          >
            {/* Subtle horizontal grid lines */}
            <line x1="0" y1="20" x2="1000" y2="20" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
            <line x1="0" y1="65" x2="1000" y2="65" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
            <line x1="0" y1="110" x2="1000" y2="110" stroke="#334155" strokeWidth="1.5" />

            {/* Bars and Axis Labels */}
            {buckets.map((b, i) => {
              const numBuckets = buckets.length;
              const slotWidth = 1000 / numBuckets;
              const barWidth = Math.max(slotWidth * 0.72, 8);
              const barX = i * slotWidth + (slotWidth - barWidth) / 2;

              // Ensure any bucket with events is visibly nonzero (minimum 10px, up to 92px)
              const scaledHeight = b.totalCount > 0
                ? Math.max(Math.round((b.totalCount / maxBucketCount) * 92), 10)
                : 0;

              const flaggedRatio = b.totalCount > 0 ? b.flaggedCount / b.totalCount : 0;
              const flaggedH = flaggedRatio > 0 ? Math.max(Math.round(scaledHeight * flaggedRatio), 4) : 0;
              const normalH = scaledHeight - flaggedH;

              const isHovered = hoveredBucket?.key === b.key;

              return (
                <g key={b.key} className="cursor-pointer">
                  {/* Hover highlight column */}
                  {isHovered && (
                    <rect
                      x={i * slotWidth}
                      y="10"
                      width={slotWidth}
                      height="100"
                      fill="rgba(20, 184, 166, 0.12)"
                      rx="3"
                    />
                  )}

                  {/* Empty bucket tick */}
                  {b.totalCount === 0 && (
                    <rect
                      x={barX}
                      y="108"
                      width={barWidth}
                      height="2"
                      fill="#1e293b"
                      rx="1"
                    />
                  )}

                  {/* Normal baseline rect */}
                  {normalH > 0 && (
                    <rect
                      x={barX}
                      y={110 - normalH}
                      width={barWidth}
                      height={normalH}
                      fill={isHovered ? '#14b8a6' : '#0d9488'}
                      rx={flaggedH > 0 ? 0 : 2}
                      className="transition-colors duration-150"
                    />
                  )}

                  {/* Flagged evidence rect (stacked on top) */}
                  {flaggedH > 0 && (
                    <rect
                      x={barX}
                      y={110 - normalH - flaggedH}
                      width={barWidth}
                      height={flaggedH}
                      fill={isHovered ? '#fb7185' : '#f43f5e'}
                      rx={2}
                      className="transition-colors duration-150"
                    />
                  )}

                  {/* X-axis time label */}
                  <text
                    x={barX + barWidth / 2}
                    y="128"
                    textAnchor="middle"
                    fill={isHovered ? '#e2e8f0' : '#94a3b8'}
                    fontSize="10.5"
                    fontFamily="JetBrains Mono, ui-monospace, monospace"
                    className="select-none"
                  >
                    {b.label}
                  </text>

                  {/* Total count badge above bar if hovered or prominent */}
                  {isHovered && b.totalCount > 0 && (
                    <text
                      x={barX + barWidth / 2}
                      y={Math.max(110 - scaledHeight - 4, 12)}
                      textAnchor="middle"
                      fill="#f8fafc"
                      fontSize="10"
                      fontWeight="bold"
                      fontFamily="JetBrains Mono, ui-monospace, monospace"
                    >
                      {b.totalCount}
                    </text>
                  )}

                  {/* Transparent full-height hit area for reliable hovering and touch */}
                  <rect
                    x={i * slotWidth}
                    y="0"
                    width={slotWidth}
                    height="145"
                    fill="transparent"
                    onMouseEnter={() => setHoveredBucket(b)}
                    onMouseLeave={() => setHoveredBucket(null)}
                  />
                </g>
              );
            })}
          </svg>
        </div>

        {/* Floating Tooltip */}
        {hoveredBucket && (
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 rounded border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">
            <div className="flex items-center gap-2">
              <Calendar className="h-3.5 w-3.5 text-teal-400" />
              <span>
                Window: <strong className="font-mono text-slate-200">{hoveredBucket.isoStart.replace('T', ' ').slice(0, 19)} UTC</strong>
              </span>
            </div>
            <div className="flex items-center gap-3 font-mono text-[11px]">
              <span>Total: <strong className="text-slate-100">{hoveredBucket.totalCount}</strong></span>
              <span>Baseline: <strong className="text-teal-400">{hoveredBucket.normalCount}</strong></span>
              <span>Flagged: <strong className="text-rose-400">{hoveredBucket.flaggedCount}</strong></span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
