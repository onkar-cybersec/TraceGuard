/**
 * TraceGuard — Defensive Security-Log Investigation Console
 * 100% Client-side deterministic threat correlation and reporting.
 */

import { AlertCircle, FileSearch, ShieldCheck } from 'lucide-react';
import React, { useMemo, useState } from 'react';
import { AffectedEntities } from './components/AffectedEntities';
import { CategoryDistribution } from './components/CategoryDistribution';
import { DashboardMetrics } from './components/DashboardMetrics';
import { EvidenceDrawer } from './components/EvidenceDrawer';
import { ExportActions } from './components/ExportActions';
import { FindingsList } from './components/FindingsList';
import { IntakeView } from './components/IntakeView';
import { ActiveTab, Navbar } from './components/Navbar';
import { PrivacyView } from './components/PrivacyView';
import { RejectedRowsModal } from './components/RejectedRowsModal';
import { RulesGuide } from './components/RulesGuide';
import { SampleModal } from './components/SampleModal';
import { SchemaHelpModal } from './components/SchemaHelpModal';
import { TimelineChart } from './components/TimelineChart';
import { detectAnomalies } from './engine/detector';
import { parseSecurityLogs } from './engine/parser';
import { DetectionCategory, DetectionFinding, DetectionResult, Severity } from './engine/types';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('investigation');
  const [result, setResult] = useState<DetectionResult | null>(null);
  const [fatalError, setFatalError] = useState<string | null>(null);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRule, setSelectedRule] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<DetectionCategory | null>(null);

  // Modals & Drawers
  const [inspectingFinding, setInspectingFinding] = useState<DetectionFinding | null>(null);
  const [isRejectedModalOpen, setIsRejectedModalOpen] = useState(false);
  const [isSchemaModalOpen, setIsSchemaModalOpen] = useState(false);
  const [isSampleModalOpen, setIsSampleModalOpen] = useState(false);

  // Handle parsing and correlation of raw log content
  const handleLoadLogContent = (content: string, fileName: string, fileSize: number) => {
    setFatalError(null);
    const parsed = parseSecurityLogs(content, fileName, fileSize);

    if (!parsed.success || parsed.fatalError) {
      setFatalError(parsed.fatalError || 'Failed to parse log file.');
      return;
    }

    const findings = detectAnomalies(parsed.events);

    setResult({
      validation: parsed.validation,
      events: parsed.events,
      findings,
    });

    // Reset filters and ensure we are on the investigation tab
    setSearchQuery('');
    setSelectedRule(null);
    setSelectedSeverity(null);
    setSelectedCategory(null);
    setActiveTab('investigation');
  };

  // Reset all state and release uploaded data from memory
  const handleReset = () => {
    setResult(null);
    setFatalError(null);
    setSearchQuery('');
    setSelectedRule(null);
    setSelectedSeverity(null);
    setSelectedCategory(null);
    setInspectingFinding(null);
    setIsRejectedModalOpen(false);
    setActiveTab('investigation');
  };

  // Filter findings based on active search and filter controls
  const filteredFindings = useMemo(() => {
    if (!result) return [];
    return result.findings.filter((f) => {
      // 1. Rule filter
      if (selectedRule && f.rule_id !== selectedRule) return false;

      // 2. Severity filter
      if (selectedSeverity && f.severity !== selectedSeverity) return false;

      // 3. Category filter
      if (selectedCategory && f.category !== selectedCategory) return false;

      // 4. Free-text search
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchesSummary = f.summary.toLowerCase().includes(q);
        const matchesExplanation = f.explanation.toLowerCase().includes(q);
        const matchesRule = f.rule_id.toLowerCase().includes(q);
        const matchesUser = f.entity_user ? f.entity_user.toLowerCase().includes(q) : false;
        const matchesIp = f.entity_source_ip ? f.entity_source_ip.toLowerCase().includes(q) : false;
        const matchesCategory = f.category.toLowerCase().includes(q);
        const matchesEvents = f.supporting_events.some(
          (e) =>
            (e.message && e.message.toLowerCase().includes(q)) ||
            (e.event_type && e.event_type.toLowerCase().includes(q)) ||
            (e.destination_ip && e.destination_ip.toLowerCase().includes(q))
        );

        return (
          matchesSummary ||
          matchesExplanation ||
          matchesRule ||
          matchesUser ||
          matchesIp ||
          matchesCategory ||
          matchesEvents
        );
      }

      return true;
    });
  }, [result, selectedRule, selectedSeverity, selectedCategory, searchQuery]);

  const isFiltered = Boolean(
    searchQuery || selectedRule || selectedSeverity || selectedCategory
  );

  return (
    <div className="min-h-screen bg-[#0B0F19] text-slate-100 flex flex-col font-sans selection:bg-teal-900 selection:text-teal-200">
      {/* Top Bar Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        hasData={result !== null}
        onReset={handleReset}
        onOpenSampleModal={() => setIsSampleModalOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-1">
        {/* TAB 1: Rules Guide */}
        {activeTab === 'rules' && <RulesGuide />}

        {/* TAB 2: Schema Documentation */}
        {activeTab === 'schema' && (
          <div className="mx-auto max-w-5xl py-8 px-4 sm:px-6">
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-6">
              <SchemaHelpModal isOpen={true} onClose={() => setActiveTab('investigation')} />
            </div>
          </div>
        )}

        {/* TAB 3: Privacy & Architecture */}
        {activeTab === 'privacy' && <PrivacyView />}

        {/* TAB 4: Investigation Console (Landing / Intake or Dashboard) */}
        {activeTab === 'investigation' && (
          <>
            {!result ? (
              <IntakeView
                onLoadLogContent={handleLoadLogContent}
                onOpenSchemaHelp={() => setIsSchemaModalOpen(true)}
                fatalError={fatalError || undefined}
              />
            ) : (
              <div className="mx-auto max-w-7xl py-6 px-4 sm:px-6 space-y-6">
                {/* Header Action Bar: Target info + Export buttons */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <FileSearch className="h-4 w-4 text-teal-400" />
                      <h2 className="text-lg font-bold text-slate-100 truncate max-w-md" title={result.validation.file_name}>
                        {result.validation.file_name}
                      </h2>
                      <span className="text-xs font-mono text-slate-500">
                        ({(result.validation.file_size_bytes / 1024).toFixed(1)} KiB)
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5 flex flex-wrap items-center gap-2">
                      <span>Analyzed: <span className="font-mono">{result.validation.analysis_timestamp_utc.slice(0, 19)} UTC</span></span>
                      <span>·</span>
                      <span>Timespan: <span className="font-mono text-slate-300">{result.validation.earliest_event_utc?.slice(11, 19)} &rarr; {result.validation.latest_event_utc?.slice(11, 19)} UTC</span></span>
                    </div>
                  </div>

                  <ExportActions result={result} />
                </div>

                {/* Dashboard Metrics KPI row */}
                <DashboardMetrics
                  validation={result.validation}
                  totalFindings={result.findings.length}
                  filteredFindingsCount={filteredFindings.length}
                  filteredFindings={filteredFindings}
                  globalFindings={result.findings}
                  isFiltered={isFiltered}
                  onOpenRejectedModal={() => setIsRejectedModalOpen(true)}
                />

                {/* UTC Event Timeline Chart */}
                <TimelineChart
                  events={result.events}
                  findings={filteredFindings}
                  allFindingsCount={result.findings.length}
                  isFiltered={isFiltered}
                />

                {/* Side-by-Side: Category breakdown & Top Entities */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                  <div className="lg:col-span-5">
                    <CategoryDistribution
                      findings={filteredFindings}
                      globalTotalCount={result.findings.length}
                      isFiltered={isFiltered}
                      activeCategoryFilter={selectedCategory}
                      onSelectCategory={setSelectedCategory}
                    />
                  </div>
                  <div className="lg:col-span-7">
                    <AffectedEntities
                      findings={filteredFindings}
                      globalTotalCount={result.findings.length}
                      isFiltered={isFiltered}
                      activeSearch={searchQuery}
                      onSelectEntitySearch={setSearchQuery}
                    />
                  </div>
                </div>

                {/* Correlated Findings List & Filters */}
                <FindingsList
                  findings={filteredFindings}
                  allFindingsCount={result.findings.length}
                  searchQuery={searchQuery}
                  setSearchQuery={setSearchQuery}
                  selectedRule={selectedRule}
                  setSelectedRule={setSelectedRule}
                  selectedSeverity={selectedSeverity}
                  setSelectedSeverity={setSelectedSeverity}
                  selectedCategory={selectedCategory}
                  setSelectedCategory={setSelectedCategory}
                  onInspectFinding={setInspectingFinding}
                />
              </div>
            )}
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-850 bg-slate-950 py-4 text-center text-xs text-slate-500">
        <div className="mx-auto max-w-7xl px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="h-3.5 w-3.5 text-teal-400" />
            <span>TraceGuard Defensive Log Investigator · Handshake AI Skills Studio</span>
          </div>
          <div>
            Processed 100% locally in browser memory · Zero remote telemetry
          </div>
        </div>
      </footer>

      {/* Drawers and Modals */}
      <EvidenceDrawer
        finding={inspectingFinding}
        onClose={() => setInspectingFinding(null)}
      />

      {result && (
        <RejectedRowsModal
          rejectedRows={result.validation.rejected_rows}
          totalRejected={result.validation.rejected_count}
          isOpen={isRejectedModalOpen}
          onClose={() => setIsRejectedModalOpen(false)}
        />
      )}

      <SchemaHelpModal
        isOpen={isSchemaModalOpen}
        onClose={() => setIsSchemaModalOpen(false)}
      />

      <SampleModal
        isOpen={isSampleModalOpen}
        onClose={() => setIsSampleModalOpen(false)}
        onLoadDirect={handleLoadLogContent}
      />
    </div>
  );
}
