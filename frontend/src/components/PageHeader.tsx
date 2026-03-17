interface PageHeaderProps {
  title: string;
  live?: boolean;
}

export function PageHeader({ title, live }: PageHeaderProps) {
  return (
    <div className="flex items-center justify-between mb-6">
      <h1 className="text-xl font-bold text-tatu-text tracking-wide">{title}</h1>
      {live && (
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-tatu-accent-glow border border-tatu-accent/25">
          <span className="w-[7px] h-[7px] rounded-full bg-tatu-accent" style={{ boxShadow: "0 0 8px #10B981" }} />
          <span className="text-[11px] text-tatu-accent font-semibold">LIVE</span>
        </div>
      )}
    </div>
  );
}
