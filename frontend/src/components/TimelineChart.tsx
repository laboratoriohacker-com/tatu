import type { TimelineBucket } from "../lib/types";

export function TimelineChart({ data }: { data: TimelineBucket[] }) {
  const maxEvents = Math.max(...data.map((d) => d.events), 1);
  return (
    <div className="flex items-end gap-1 h-32">
      {data.map((bucket) => (
        <div key={bucket.hour} className="flex-1 flex flex-col items-center gap-1">
          <div className="w-full relative" style={{ height: "100px" }}>
            <div
              className="absolute bottom-0 w-full rounded-t bg-tatu-accent/40"
              style={{ height: `${(bucket.events / maxEvents) * 100}%` }}
            />
            <div
              className="absolute bottom-0 w-full rounded-t bg-tatu-critical/60"
              style={{ height: `${(bucket.blocks / maxEvents) * 100}%` }}
            />
          </div>
          <span className="text-[8px] text-tatu-text-dim">{bucket.hour}</span>
        </div>
      ))}
    </div>
  );
}
