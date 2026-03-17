# Live Alerts Pagination

**Date:** 2026-03-16
**Status:** Draft

## Problem

The LiveAlerts page hardcodes `per_page: 50` and has no pagination UI. Users can only see the most recent 50 alerts plus any new WebSocket events. There is no way to browse older alerts.

## Solution

Add pagination controls to the LiveAlerts page, matching the existing AuditLog pagination pattern. Handle WebSocket events gracefully: on page 1 they prepend as today; on page 2+ a banner notifies the user.

## Design

### File Changed

Only `frontend/src/pages/LiveAlerts.tsx` changes. No backend or API client changes needed — the `/api/v1/alerts` endpoint already supports `page` and `per_page` parameters.

### State Changes

Add `page` state:
```tsx
const [page, setPage] = useState(1);
```

Update the `useApi` call to include `page` in params and dependencies:
```tsx
const { data, loading } = useApi<PaginatedResponse<Event>>(
  () => api.getAlerts({ page: String(page), per_page: "50" }) as Promise<PaginatedResponse<Event>>,
  [page],
);
```

Extract `totalPages`:
```tsx
const totalPages = data?.pages ?? 1;
```

### WebSocket + Pagination Interaction

- **Page 1:** Live events prepend to the list as today (no change).
- **Page 2+:** Live events still accumulate in `liveEvents` state but are excluded from display. A banner appears: "New alerts available" with a button/link that sets `page` to 1.

Change `allEvents` to conditionally include live events:
```tsx
const allEvents = page === 1 ? [...liveEvents, ...(data?.items ?? [])] : (data?.items ?? []);
```

Add a `newAlertCount` derived value:
```tsx
const newAlertCount = page > 1 ? liveEvents.length : 0;
```

### Filter Reset

When the severity filter changes, reset to page 1:
```tsx
const handleFilterChange = (sev: SeverityFilter) => {
  setFilter(sev);
  setPage(1);
};
```

Update filter buttons to use `handleFilterChange` instead of `setFilter` directly.

### Pagination UI

Add after the alert cards div, before the AlertDetail modal — same markup as AuditLog lines 105-123:

```tsx
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
```

### New Alerts Banner

When `newAlertCount > 0`, show a banner above the alert cards:

```tsx
{newAlertCount > 0 && (
  <button
    onClick={() => { setPage(1); setLiveEvents([]); }}
    className="w-full mb-3 px-3 py-2 rounded text-[11px] font-semibold border border-tatu-accent/30 bg-tatu-accent/10 text-tatu-accent hover:bg-tatu-accent/20 transition-colors"
  >
    {newAlertCount} new alert{newAlertCount > 1 ? "s" : ""} available — click to view
  </button>
)}
```

Clicking the banner navigates to page 1 and clears accumulated live events to avoid duplicates (since page 1 API response will include the newest alerts).

### Test Plan

1. Manual: Load LiveAlerts, verify pagination buttons appear when >50 alerts
2. Manual: Click Next/Previous, verify correct page loads
3. Manual: Change severity filter, verify page resets to 1
4. Manual: Navigate to page 2, verify new WebSocket alerts show banner instead of prepending
5. Manual: Click banner, verify return to page 1 with fresh data
6. Lint: `make lint` passes
