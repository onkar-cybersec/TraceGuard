import { Download, RotateCcw, Shield } from 'lucide-react';
import React from 'react';

export type ActiveTab = 'investigation' | 'rules' | 'schema' | 'privacy';

interface NavbarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  hasData: boolean;
  onReset: () => void;
  onOpenSampleModal: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  hasData,
  onReset,
  onOpenSampleModal,
}) => {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6">
        {/* Zone 1: Single text element wordmark */}
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-teal-400 shrink-0" aria-hidden="true" />
          <button
            onClick={() => setActiveTab('investigation')}
            className="text-left font-bold tracking-tight text-slate-100 hover:text-teal-300 transition-colors cursor-pointer"
          >
            TraceGuard
          </button>
          <span className="hidden sm:inline text-xs text-slate-500 font-mono tracking-normal">
            v1.0 · SOC Log Investigation
          </span>
        </div>

        {/* Zone 2: Clean text navigation links */}
        <nav className="flex items-center gap-1 sm:gap-6 text-xs sm:text-sm font-medium text-slate-400">
          <button
            onClick={() => setActiveTab('investigation')}
            className={`transition-colors py-1 cursor-pointer ${
              activeTab === 'investigation'
                ? 'text-teal-400 font-semibold border-b-2 border-teal-400'
                : 'hover:text-slate-200'
            }`}
          >
            Investigation
          </button>
          <button
            onClick={() => setActiveTab('rules')}
            className={`transition-colors py-1 cursor-pointer ${
              activeTab === 'rules'
                ? 'text-teal-400 font-semibold border-b-2 border-teal-400'
                : 'hover:text-slate-200'
            }`}
          >
            Detection Rules
          </button>
          <button
            onClick={() => setActiveTab('schema')}
            className={`transition-colors py-1 cursor-pointer hidden md:inline-block ${
              activeTab === 'schema'
                ? 'text-teal-400 font-semibold border-b-2 border-teal-400'
                : 'hover:text-slate-200'
            }`}
          >
            Schema & Aliases
          </button>
          <button
            onClick={() => setActiveTab('privacy')}
            className={`transition-colors py-1 cursor-pointer hidden sm:inline-block ${
              activeTab === 'privacy'
                ? 'text-teal-400 font-semibold border-b-2 border-teal-400'
                : 'hover:text-slate-200'
            }`}
          >
            Architecture & Privacy
          </button>
        </nav>

        {/* Zone 3: Primary action buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={onOpenSampleModal}
            className="flex items-center gap-1.5 rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 hover:border-slate-600 transition-colors cursor-pointer whitespace-nowrap"
            title="Download synthetic test datasets"
          >
            <Download className="h-3.5 w-3.5 text-teal-400" />
            <span className="hidden sm:inline">Samples</span>
          </button>

          {hasData && (
            <button
              onClick={onReset}
              className="flex items-center gap-1.5 rounded border border-rose-900/40 bg-rose-950/20 px-2.5 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-900/30 hover:border-rose-800 transition-colors cursor-pointer whitespace-nowrap"
              title="Clear all log data and reset application state"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
