import { useState } from "react";
import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import type {
  OverviewStats,
  TimelineBucket,
  PaginatedResponse,
  Event,
  RuleWithStats,
  ComplianceResponse,
} from "../lib/types";
import { PageHeader } from "../components/PageHeader";
import { StatCard } from "../components/StatCard";
import { TimelineChart } from "../components/TimelineChart";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusDot } from "../components/StatusDot";
import { ComplianceGauge } from "../components/ComplianceGauge";
import { Panel } from "../components/Panel";
import { AlertDetail } from "../components/AlertDetail";

export function Overview() {
  const stats = useApi<OverviewStats>(() => api.getOverviewStats() as Promise<OverviewStats>, []);
  const timeline = useApi<TimelineBucket[]>(() => api.getTimeline() as Promise<TimelineBucket[]>, []);
  const alerts = useApi<PaginatedResponse<Event>>(
    () => api.getAlerts({ per_page: "5" }) as Promise<PaginatedResponse<Event>>,
    [],
  );
  const topRules = useApi<RuleWithStats[]>(() => api.getTopRules() as Promise<RuleWithStats[]>, []);
  const compliance = useApi<ComplianceResponse>(() => api.getCompliance() as Promise<ComplianceResponse>, []);

  const [selected, setSelected] = useState<Event | null>(null);

  const loading = stats.loading || timeline.loading || alerts.loading || topRules.loading || compliance.loading;

  if (loading) {
    return (
      <div>
        <PageHeader title="AI-Assisted Security Overview" />
        <p className="text-tatu-text-muted text-sm">Loading...</p>
      </div>
    );
  }

  const topRulesList = topRules.data
    ? [...topRules.data].sort((a, b) => parseFloat(b.block_rate) - parseFloat(a.block_rate)).slice(0, 5)
    : [];

  return (
    <div>
      <PageHeader title="AI-Assisted Security Overview" />

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Events" value={stats.data?.total_events ?? 0} />
        <StatCard label="Blocks" value={stats.data?.total_blocks ?? 0} color="tatu-critical" />
        <StatCard label="Active Sessions" value={stats.data?.active_sessions ?? 0} color="tatu-info" />
        <StatCard label="Secrets Caught" value={stats.data?.secrets_caught ?? 0} color="tatu-warn" />
      </div>

      {/* Timeline */}
      <Panel className="mb-6">
        <h2 className="text-sm font-semibold text-tatu-text mb-3">24h Event Timeline</h2>
        {timeline.data && <TimelineChart data={timeline.data} />}
      </Panel>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Recent Alerts */}
        <Panel>
          <h2 className="text-sm font-semibold text-tatu-text mb-3">Recent Alerts</h2>
          <div className="space-y-2">
            {alerts.data?.items.map((alert) => (
              <div
                key={alert.id}
                className="flex items-center gap-3 text-xs py-2 border-b border-tatu-border last:border-0 cursor-pointer hover:bg-tatu-surface-alt/30 transition-colors"
                onClick={() => setSelected(alert)}
              >
                <StatusDot status={alert.status} />
                <SeverityBadge severity={alert.severity} />
                <span className="text-tatu-text flex-1 truncate">{alert.message}</span>
                <span className="text-tatu-text-dim">{alert.developer}</span>
              </div>
            ))}
            {(!alerts.data || alerts.data.items.length === 0) && (
              <p className="text-tatu-text-dim text-xs">No recent alerts</p>
            )}
          </div>
        </Panel>

        {/* Top Rules by Block Rate */}
        <Panel>
          <h2 className="text-sm font-semibold text-tatu-text mb-3">Top Rules by Block Rate</h2>
          <div className="space-y-2">
            {topRulesList.map((rule) => (
              <div
                key={rule.id}
                className="flex items-center justify-between text-xs py-2 border-b border-tatu-border last:border-0"
              >
                <span className="text-tatu-text">{rule.name}</span>
                <span className="text-tatu-critical font-semibold">{rule.block_rate}%</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* Compliance Gauges */}
      <Panel>
        <h2 className="text-sm font-semibold text-tatu-text mb-3">Compliance</h2>
        <div className="space-y-3">
          {compliance.data?.frameworks.map((fw) => (
            <ComplianceGauge key={fw.framework} data={fw} />
          ))}
        </div>
      </Panel>

      {selected && <AlertDetail alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
