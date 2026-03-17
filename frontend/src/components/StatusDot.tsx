const STATUS_COLORS: Record<string, string> = {
  blocked: "#EF4444",
  warning: "#F59E0B",
  allowed: "#10B981",
  clean: "#10B981",
};

export function StatusDot({ status }: { status: string }) {
  const color = STATUS_COLORS[status] || "#64748B";
  return (
    <span
      className="inline-block w-[7px] h-[7px] rounded-full"
      style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}80` }}
    />
  );
}
