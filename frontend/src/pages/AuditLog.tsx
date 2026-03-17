import { useState } from "react";
import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import type { PaginatedResponse, Event } from "../lib/types";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";

const STATUS_LABELS: Record<string, string> = {
  blocked: "DENY",
  warning: "WARN",
  allowed: "ALLOW",
  clean: "PASS",
  audit_block: "AUDIT",
};

const STATUS_STYLES: Record<string, string> = {
  DENY: "bg-tatu-critical/15 text-tatu-critical",
  WARN: "bg-tatu-warn/15 text-tatu-warn",
  ALLOW: "bg-tatu-accent/15 text-tatu-accent",
  PASS: "bg-tatu-accent/15 text-tatu-accent",
  AUDIT: "bg-tatu-info/15 text-tatu-info",
};

export function AuditLog() {
  const [page, setPage] = useState(1);

  const { data, loading } = useApi<PaginatedResponse<Event>>(
    () => api.getAudit({ page: String(page), per_page: "20" }) as Promise<PaginatedResponse<Event>>,
    [page],
  );

  const items = data?.items ?? [];
  const totalPages = data?.pages ?? 1;

  return (
    <div>
      <PageHeader title="Audit Log" />

      {/* Export Buttons */}
      <div className="flex gap-2 mb-5">
        <a
          href={api.getAuditExportUrl("csv")}
          className="px-3 py-1.5 rounded text-[11px] font-semibold uppercase tracking-wider border border-tatu-border bg-tatu-surface text-tatu-text-muted hover:border-tatu-border-hover transition-colors"
        >
          Export CSV
        </a>
        <a
          href={api.getAuditExportUrl("json")}
          className="px-3 py-1.5 rounded text-[11px] font-semibold uppercase tracking-wider border border-tatu-border bg-tatu-surface text-tatu-text-muted hover:border-tatu-border-hover transition-colors"
        >
          Export JSON
        </a>
      </div>

      {loading && <p className="text-tatu-text-muted text-sm">Loading...</p>}

      {!loading && (
        <Panel className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-tatu-border">
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Timestamp
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Developer
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Hook
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Event Detail
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Result
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((event) => {
                const label = STATUS_LABELS[event.status] ?? event.status.toUpperCase();
                const style = STATUS_STYLES[label] ?? "bg-tatu-surface-alt text-tatu-text-dim";
                return (
                  <tr key={event.id} className="border-b border-tatu-border/50 hover:bg-tatu-surface-alt/50">
                    <td className="py-2.5 px-3 text-tatu-text-muted whitespace-nowrap">
                      {new Date(event.timestamp).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-tatu-text">{event.developer}</td>
                    <td className="py-2.5 px-3 text-tatu-text-muted">{event.hook_name}</td>
                    <td className="py-2.5 px-3 text-tatu-text-muted truncate max-w-[300px]">{event.message}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase ${style}`}
                      >
                        {label}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Pagination */}
          <div className="flex items-center justify-between mt-4 pt-3 border-t border-tatu-border">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="px-3 py-1.5 rounded text-[11px] font-semibold border border-tatu-border bg-tatu-surface text-tatu-text-muted hover:border-tatu-border-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              Previous
            </button>
            <span className="text-[11px] text-tatu-text-dim">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-3 py-1.5 rounded text-[11px] font-semibold border border-tatu-border bg-tatu-surface text-tatu-text-muted hover:border-tatu-border-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              Next
            </button>
          </div>
        </Panel>
      )}
    </div>
  );
}
