import type { ComplianceFramework } from "../lib/types";

export function ComplianceGauge({ data }: { data: ComplianceFramework }) {
  const configuredPct = data.controls > 0 ? Math.min(Math.round((data.covered / data.controls) * 100), 100) : 0;
  const evidencedPct = data.controls > 0 ? Math.min(Math.round((data.evidenced / data.controls) * 100), 100) : 0;

  return (
    <div className="flex items-center gap-3">
      <div className="w-24 text-xs text-tatu-text font-semibold">{data.framework}</div>
      <div className="flex-1 h-2 bg-tatu-surface-alt rounded-full overflow-hidden relative">
        {/* Configured layer (dimmer) */}
        <div
          className="absolute inset-y-0 left-0 bg-tatu-accent/30 rounded-full transition-all"
          style={{ width: `${configuredPct}%` }}
        />
        {/* Evidenced layer (bright) */}
        <div
          className="absolute inset-y-0 left-0 bg-tatu-accent rounded-full transition-all"
          style={{ width: `${evidencedPct}%` }}
        />
      </div>
      <div className="text-xs text-tatu-text-muted w-24 text-right">
        <span className="text-tatu-accent font-semibold">{data.evidenced}</span>
        <span className="text-tatu-text-dim">/{data.covered}</span>
        <span className="text-tatu-text-dim">/{data.controls}</span>
      </div>
    </div>
  );
}
