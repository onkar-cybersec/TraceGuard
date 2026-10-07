import { Code2, HelpCircle, X } from 'lucide-react';
import React from 'react';
import { FIELD_ALIASES } from '../engine/parser';

interface SchemaHelpModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SchemaHelpModal: React.FC<SchemaHelpModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-4xl max-h-[85vh] rounded-lg border border-slate-800 bg-slate-900 shadow-2xl flex flex-col overflow-hidden text-slate-100"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="border-b border-slate-800 px-6 py-4 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2">
            <Code2 className="h-5 w-5 text-teal-400" />
            <div>
              <h3 className="text-sm font-bold text-slate-100">
                Log Schema & Field Aliases Specification
              </h3>
              <p className="text-xs text-slate-400">
                Supported field mappings for JSON arrays and CSV headers.
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

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs">
          {/* Required Fields */}
          <div>
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-2">
              Mandatory Fields (Required on Every Event)
            </h4>
            <div className="rounded border border-slate-800 overflow-hidden">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-950 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                    <th className="p-2.5 w-36">Canonical Field</th>
                    <th className="p-2.5 w-32">Type & Format</th>
                    <th className="p-2.5">Supported Aliases</th>
                    <th className="p-2.5">Validation Rule</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850">
                  <tr>
                    <td className="p-2.5 font-mono text-teal-400 font-semibold">event_type</td>
                    <td className="p-2.5 font-mono text-slate-300">string</td>
                    <td className="p-2.5 font-mono text-slate-400">
                      action, type, event, activity, operation, event_name
                    </td>
                    <td className="p-2.5 text-slate-300">
                      Non-empty string describing the action (e.g. user_login, egress).
                    </td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-mono text-teal-400 font-semibold">timestamp</td>
                    <td className="p-2.5 font-mono text-slate-300">ISO 8601 string</td>
                    <td className="p-2.5 font-mono text-slate-400">
                      time, datetime, @timestamp, event_time, date
                    </td>
                    <td className="p-2.5 text-slate-300">
                      Must contain explicit timezone suffix (e.g. <code className="text-teal-300 font-mono">2026-10-07T12:00:00Z</code> or <code className="text-teal-300 font-mono">+00:00</code>).
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Optional Fields */}
          <div>
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-2">
              Optional Correlation Fields
            </h4>
            <div className="rounded border border-slate-800 overflow-hidden">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-950 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                    <th className="p-2.5 w-36">Canonical Field</th>
                    <th className="p-2.5 w-32">Type</th>
                    <th className="p-2.5">Supported Aliases</th>
                    <th className="p-2.5">Validation & Correlation Role</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850 text-slate-300">
                  <tr>
                    <td className="p-2.5 font-mono text-teal-400 font-semibold">user</td>
                    <td className="p-2.5 font-mono text-slate-400">string</td>
                    <td className="p-2.5 font-mono text-slate-400">
                      username, account, user_name, principal, subject
                    </td>
                    <td className="p-2.5">Account identity. Correlated in TG001, TG002, TG003.</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-mono text-teal-400 font-semibold">source_ip</td>
                    <td className="p-2.5 font-mono text-slate-400">IPv4 / IPv6</td>
                    <td className="p-2.5 font-mono text-slate-400">
                      src_ip, client_ip, source_address, src_addr, ip, clientip
                    </td>
                    <td className="p-2.5">Originating address. Validated syntax. Correlated in TG001, TG002.</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-mono text-teal-400 font-semibold">destination_ip</td>
                    <td className="p-2.5 font-mono text-slate-400">IPv4 / IPv6</td>
                    <td className="p-2.5 font-mono text-slate-400">
                      dest_ip, dst_ip, server_ip, remote_ip, dst_addr
                    </td>
                    <td className="p-2.5">Target address. Classified as public vs reserved for TG004.</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-mono text-teal-400 font-semibold">destination_port</td>
                    <td className="p-2.5 font-mono text-slate-400">integer (1..65535)</td>
                    <td className="p-2.5 font-mono text-slate-400">
                      dest_port, dst_port, port, remote_port, dstport
                    </td>
                    <td className="p-2.5">Target port. Ports 4444 and 1337 flag TG004 egress.</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-mono text-teal-400 font-semibold">bytes</td>
                    <td className="p-2.5 font-mono text-slate-400">integer (&ge; 0)</td>
                    <td className="p-2.5 font-mono text-slate-400">
                      size, bytes_sent, bytes_transferred, bytes_out, payload_size
                    </td>
                    <td className="p-2.5">Egress size. Transfers &ge; 10,485,760 bytes to public IPs flag TG004.</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-mono text-teal-400 font-semibold">status</td>
                    <td className="p-2.5 font-mono text-slate-400">string</td>
                    <td className="p-2.5 font-mono text-slate-400">
                      result, outcome, action_status, state
                    </td>
                    <td className="p-2.5">"failure" / "denied" vs "success" / "ok" drives TG001 & TG002.</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-mono text-teal-400 font-semibold">new_role</td>
                    <td className="p-2.5 font-mono text-slate-400">string</td>
                    <td className="p-2.5 font-mono text-slate-400">
                      role, assigned_role, target_role, granted_role
                    </td>
                    <td className="p-2.5">Role granted. "admin", "root", "administrator", "superuser" flags TG003.</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-mono text-teal-400 font-semibold">message</td>
                    <td className="p-2.5 font-mono text-slate-400">string</td>
                    <td className="p-2.5 font-mono text-slate-400">
                      msg, description, details, log_message, summary
                    </td>
                    <td className="p-2.5">Event details payload. Automatically scanned for TG005 secrets.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-slate-800 px-6 py-3 bg-slate-950/60 flex items-center justify-between text-xs text-slate-400">
          <span>Aliases are case-insensitive and hyphen/underscore tolerant</span>
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
