import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import type { DeveloperStats } from "../lib/types";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";

export function Developers() {
  const { data, loading } = useApi<DeveloperStats[]>(
    () => api.getDevelopers() as Promise<DeveloperStats[]>,
    [],
  );

  if (loading) {
    return (
      <div>
        <PageHeader title="Developers" />
        <p className="text-tatu-text-muted text-sm">Loading...</p>
      </div>
    );
  }

  const developers = data ?? [];
  const maxSessions = Math.max(...developers.map((d) => d.sessions), 1);

  return (
    <div>
      <PageHeader title="Developers" />

      <Panel className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-tatu-border">
              <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                Developer
              </th>
              <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                Sessions
              </th>
              <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                Blocks
              </th>
              <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                Risk Level
              </th>
            </tr>
          </thead>
          <tbody>
            {developers.map((dev) => (
              <tr key={dev.name} className="border-b border-tatu-border/50 hover:bg-tatu-surface-alt/50">
                <td className="py-2.5 px-3 text-tatu-text font-medium">{dev.name}</td>
                <td className="py-2.5 px-3">
                  <div className="flex items-center gap-2">
                    <span className="text-tatu-text-muted w-8">{dev.sessions}</span>
                    <div className="flex-1 h-1.5 bg-tatu-surface-alt rounded-full overflow-hidden max-w-[120px]">
                      <div
                        className="h-full bg-tatu-accent rounded-full"
                        style={{ width: `${(dev.sessions / maxSessions) * 100}%` }}
                      />
                    </div>
                  </div>
                </td>
                <td className="py-2.5 px-3 text-tatu-text-muted">{dev.blocks}</td>
                <td className="py-2.5 px-3">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase ${
                      dev.risk === "high"
                        ? "bg-tatu-critical/15 text-tatu-critical"
                        : "bg-tatu-accent/15 text-tatu-accent"
                    }`}
                  >
                    {dev.risk}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
