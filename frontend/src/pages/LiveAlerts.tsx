import { useState, useCallback } from "react";
import { useApi } from "../hooks/useApi";
import { useWebSocket } from "../hooks/useWebSocket";
import { api } from "../lib/api";
import type { PaginatedResponse, Event } from "../lib/types";
import { PageHeader } from "../components/PageHeader";
import { SeverityBadge } from "../components/SeverityBadge";
import { Panel } from "../components/Panel";
import { AlertDetail } from "../components/AlertDetail";

const SEVERITY_FILTERS = ["all", "critical", "warning", "info", "audit"] as const;
type SeverityFilter = (typeof SEVERITY_FILTERS)[number];

export function LiveAlerts() {
  const [filter, setFilter] = useState<SeverityFilter>("all");
  const [page, setPage] = useState(1);
  const [liveEvents, setLiveEvents] = useState<Event[]>([]);
  const [selected, setSelected] = useState<Event | null>(null);

  const { data, loading } = useApi<PaginatedResponse<Event>>(
    () => api.getAlerts({ page: String(page), per_page: "50" }) as Promise<PaginatedResponse<Event>>,
    [page],
  );

  const totalPages = data?.pages ?? 1;

  const onMessage = useCallback((msg: unknown) => {
    const event = msg as Event;
    if (event && typeof event === "object" && "id" in event) {
      setLiveEvents((prev) => [event, ...prev]);
    }
  }, []);

  const { connected } = useWebSocket(onMessage);

  const allEvents = page === 1 ? [...liveEvents, ...(data?.items ?? [])] : (data?.items ?? []);
  const filtered =
    filter === "all"
      ? allEvents
      : filter === "audit"
        ? allEvents.filter((e) => e.status === "audit_block")
        : allEvents.filter((e) => e.severity === filter);

  const newAlertCount = page > 1 ? liveEvents.length : 0;

  const handleFilterChange = (sev: SeverityFilter) => {
    setFilter(sev);
    setPage(1);
  };

  return (
    <div>
      <PageHeader title="Live Alerts" live={connected} />

      {/* Severity Filter */}
      <div className="flex gap-2 mb-5">
        {SEVERITY_FILTERS.map((sev) => (
          <button
            key={sev}
            onClick={() => handleFilterChange(sev)}
            className={`px-3 py-1.5 rounded text-[11px] font-semibold uppercase tracking-wider border transition-colors ${
              filter === sev
                ? "bg-tatu-accent/20 border-tatu-accent text-tatu-accent"
                : "bg-tatu-surface border-tatu-border text-tatu-text-muted hover:border-tatu-border-hover"
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {loading && <p className="text-tatu-text-muted text-sm">Loading...</p>}

      {/* New alerts banner */}
      {newAlertCount > 0 && (
        <button
          onClick={() => { setPage(1); setLiveEvents([]); }}
          className="w-full mb-3 px-3 py-2 rounded text-[11px] font-semibold border border-tatu-accent/30 bg-tatu-accent/10 text-tatu-accent hover:bg-tatu-accent/20 transition-colors"
        >
          {newAlertCount} new alert{newAlertCount > 1 ? "s" : ""} available — click to view
        </button>
      )}

      {/* Alert Cards */}
      <div className="space-y-3">
        {filtered.map((event) => (
          <Panel key={event.id} className="cursor-pointer hover:border-tatu-accent/30 transition-colors" onClick={() => setSelected(event)}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1.5">
                  <SeverityBadge severity={event.severity} />
                  <span className="text-xs text-tatu-text font-semibold">{event.hook_name}</span>
                </div>
                <p className="text-sm text-tatu-text mb-1 truncate">{event.message}</p>
                <div className="flex gap-4 text-[11px] text-tatu-text-dim">
                  <span>{event.developer}</span>
                  <span>{event.repository}</span>
                </div>
              </div>
              <span className="text-[10px] text-tatu-text-dim whitespace-nowrap">
                {new Date(event.timestamp).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo", day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </span>
            </div>
          </Panel>
        ))}
        {!loading && filtered.length === 0 && (
          <p className="text-tatu-text-dim text-sm">No alerts matching filter</p>
        )}
      </div>

      {/* Pagination */}
      {!loading && totalPages > 1 && (
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
      )}

      {selected && <AlertDetail alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
