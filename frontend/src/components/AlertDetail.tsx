import type { Event } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";
import { StatusDot } from "./StatusDot";
import { Panel } from "./Panel";

function DetailRow({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="flex justify-between items-start gap-4 py-1.5 border-b border-tatu-border last:border-0">
      <span className="text-[11px] text-tatu-text-muted uppercase tracking-wider shrink-0">
        {label}
      </span>
      <span className="text-xs text-tatu-text font-mono text-right truncate">
        {value ?? "—"}
      </span>
    </div>
  );
}

export function AlertDetail({ alert, onClose }: { alert: Event; onClose: () => void }) {
  const metadataEntries = Object.entries(alert.metadata_ ?? {});

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 z-40"
        onClick={onClose}
      />

      {/* Sidebar */}
      <div className="fixed top-0 right-0 h-full w-full max-w-md bg-tatu-bg border-l border-tatu-border z-50 overflow-y-auto shadow-2xl animate-slide-in-right">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-tatu-border">
          <h2 className="text-sm font-semibold text-tatu-text">Alert Detail</h2>
          <button
            onClick={onClose}
            className="text-tatu-text-muted hover:text-tatu-text text-lg leading-none"
          >
            &times;
          </button>
        </div>

        <div className="p-5 space-y-5">
          {/* Status + Severity */}
          <div className="flex items-center gap-3">
            <StatusDot status={alert.status} />
            <SeverityBadge severity={alert.severity} />
            <span className="text-xs text-tatu-text-dim">{alert.status}</span>
          </div>

          {/* Message */}
          <Panel>
            <p className="text-sm text-tatu-text">{alert.message}</p>
          </Panel>

          {/* Details */}
          <div>
            <h3 className="text-[11px] text-tatu-text-muted uppercase tracking-wider mb-2">
              Details
            </h3>
            <DetailRow label="Hook" value={alert.hook_name} />
            <DetailRow label="Event" value={alert.hook_event} />
            <DetailRow label="Developer" value={alert.developer} />
            <DetailRow label="Repository" value={alert.repository} />
            <DetailRow label="Tool" value={alert.tool_name} />
            <DetailRow label="Session" value={alert.session_id} />
            <DetailRow
              label="Time"
              value={new Date(alert.timestamp).toLocaleString()}
            />
          </div>

          {/* Metadata */}
          {metadataEntries.length > 0 && (
            <div>
              <h3 className="text-[11px] text-tatu-text-muted uppercase tracking-wider mb-2">
                Metadata
              </h3>
              {metadataEntries.map(([key, value]) => (
                <DetailRow
                  key={key}
                  label={key}
                  value={typeof value === "string" ? value : JSON.stringify(value)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
