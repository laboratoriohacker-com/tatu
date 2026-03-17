import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import type { ComplianceResponse } from "../lib/types";
import { PageHeader } from "../components/PageHeader";
import { StatCard } from "../components/StatCard";
import { ComplianceGauge } from "../components/ComplianceGauge";
import { Panel } from "../components/Panel";

export function Compliance() {
  const { data, loading } = useApi<ComplianceResponse>(
    () => api.getCompliance() as Promise<ComplianceResponse>,
    [],
  );

  if (loading) {
    return (
      <div>
        <PageHeader title="Compliance" />
        <p className="text-tatu-text-muted text-sm">Loading...</p>
      </div>
    );
  }

  const frameworks = data?.frameworks ?? [];
  const mappings = data?.mappings ?? [];

  return (
    <div>
      <PageHeader title="Compliance" />

      {/* Framework Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {frameworks.map((fw) => (
          <StatCard
            key={fw.framework}
            label={fw.framework}
            value={`${fw.percentage}%`}
            subtitle={`${fw.evidenced} of ${fw.covered} evidenced`}
            color={fw.percentage >= 80 ? "tatu-accent" : fw.percentage >= 50 ? "tatu-warn" : "tatu-critical"}
          />
        ))}
      </div>

      {/* Compliance Gauges */}
      <Panel className="mb-6">
        <h2 className="text-sm font-semibold text-tatu-text mb-3">Coverage</h2>
        <div className="space-y-3">
          {frameworks.map((fw) => (
            <ComplianceGauge key={fw.framework} data={fw} />
          ))}
        </div>
      </Panel>

      {/* Control Mapping Table */}
      <Panel className="overflow-x-auto">
        <h2 className="text-sm font-semibold text-tatu-text mb-3">Control Mappings</h2>
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-tatu-border">
              <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                Hook Name
              </th>
              <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                Mapped Controls
              </th>
            </tr>
          </thead>
          <tbody>
            {mappings.map((m, idx) => (
              <tr key={idx} className="border-b border-tatu-border/50 hover:bg-tatu-surface-alt/50">
                <td className="py-2.5 px-3 text-tatu-text font-medium">{m.hook}</td>
                <td className="py-2.5 px-3 text-tatu-text-muted">{m.maps}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
