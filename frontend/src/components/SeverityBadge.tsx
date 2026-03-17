const SEVERITY_STYLES = {
  critical: "bg-tatu-critical-dim text-tatu-critical",
  warning: "bg-tatu-warn-dim text-tatu-warn",
  info: "bg-tatu-info-dim text-tatu-info",
};

export function SeverityBadge({ severity }: { severity: "critical" | "warning" | "info" }) {
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase ${SEVERITY_STYLES[severity]}`}>
      {severity}
    </span>
  );
}
