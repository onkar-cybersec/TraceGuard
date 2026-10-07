import { Download, FileCode, FileText } from 'lucide-react';
import React from 'react';
import { generateRedactedJsonExport, generateSelfContainedHtmlReport } from '../engine/reportGenerator';
import { DetectionResult } from '../engine/types';

interface ExportActionsProps {
  result: DetectionResult;
}

export const ExportActions: React.FC<ExportActionsProps> = ({ result }) => {
  const downloadBlob = (content: string, filename: string, mimeType: string) => {
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

  const handleExportJson = () => {
    const jsonStr = generateRedactedJsonExport(result);
    const cleanFileName = result.validation.file_name.replace(/\.[^/.]+$/, '');
    downloadBlob(jsonStr, `traceguard_${cleanFileName}_redacted.json`, 'application/json');
  };

  const handleExportHtml = () => {
    const htmlStr = generateSelfContainedHtmlReport(result.validation, result.findings);
    const cleanFileName = result.validation.file_name.replace(/\.[^/.]+$/, '');
    downloadBlob(htmlStr, `traceguard_${cleanFileName}_audit_report.html`, 'text/html');
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        onClick={handleExportJson}
        className="flex items-center gap-1.5 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-800 hover:border-slate-600 transition-colors cursor-pointer"
        title="Download sanitized, secret-redacted JSON dataset"
      >
        <FileCode className="h-3.5 w-3.5 text-teal-400" />
        <span>Download Redacted JSON</span>
      </button>

      <button
        onClick={handleExportHtml}
        className="flex items-center gap-1.5 rounded bg-teal-600 hover:bg-teal-500 px-3 py-1.5 text-xs font-semibold text-slate-950 transition-colors cursor-pointer"
        title="Download standalone self-contained HTML audit report"
      >
        <FileText className="h-3.5 w-3.5 fill-current" />
        <span>Download Standalone HTML Report</span>
      </button>
    </div>
  );
};
