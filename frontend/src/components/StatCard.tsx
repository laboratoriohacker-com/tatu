interface StatCardProps {
  label: string;
  value: string | number;
  subtitle?: string;
  color?: string;
}

export function StatCard({ label, value, subtitle, color = "tatu-accent" }: StatCardProps) {
  return (
    <div className="bg-tatu-surface border border-tatu-border rounded-lg p-5 relative overflow-hidden">
      <div className={`absolute top-0 left-0 right-0 h-0.5 bg-${color}`} />
      <div className="text-[10px] text-tatu-text-dim uppercase tracking-[1.5px] mb-2">{label}</div>
      <div className={`text-3xl font-bold text-${color} leading-tight`}>{value}</div>
      {subtitle && <div className="text-[11px] text-tatu-text-dim mt-1.5">{subtitle}</div>}
    </div>
  );
}
