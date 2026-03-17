import { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import type { Rule } from "../lib/types";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";
import { SeverityBadge } from "../components/SeverityBadge";

export function Rules() {
  const { data, loading } = useApi<Rule[]>(() => api.getRules() as Promise<Rule[]>, []);
  const [activeCategory, setActiveCategory] = useState<string>("All");
  const [search, setSearch] = useState("");
  const navigate = useNavigate();

  const categories = useMemo(() => {
    if (!data) return ["All"];
    const cats = Array.from(new Set(data.map((r) => r.category)));
    return ["All", ...cats.sort()];
  }, [data]);

  const filtered = useMemo(() => {
    if (!data) return [];
    let rules = activeCategory === "All" ? data : data.filter((r) => r.category === activeCategory);
    if (search.trim()) {
      const q = search.toLowerCase();
      rules = rules.filter(
        (r) =>
          r.name.toLowerCase().includes(q) ||
          r.id.toLowerCase().includes(q) ||
          r.content.toLowerCase().includes(q),
      );
    }
    return rules;
  }, [data, activeCategory, search]);

  const filterBtnClass = (cat: string) =>
    `px-3 py-1 rounded text-[10px] font-semibold tracking-wider uppercase transition-colors ${
      activeCategory === cat
        ? "bg-tatu-accent text-tatu-bg"
        : "bg-tatu-surface-alt text-tatu-text-dim hover:text-tatu-text"
    }`;

  const thClass =
    "text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3";

  return (
    <div>
      <PageHeader title="Rules" />

      {loading && <p className="text-tatu-text-muted text-sm">Loading...</p>}

      {!loading && (
        <>
          {/* Search */}
          <div className="mb-4">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by name, id, or compliance control..."
              className="w-full max-w-md bg-tatu-surface border border-tatu-border rounded-lg px-3 py-2 text-xs text-tatu-text placeholder:text-tatu-text-dim outline-none focus:border-tatu-accent transition-colors"
            />
          </div>

          {/* Category filters */}
          <div className="flex flex-wrap gap-2 mb-4">
            {categories.map((cat) => (
              <button key={cat} className={filterBtnClass(cat)} onClick={() => setActiveCategory(cat)}>
                {cat}
              </button>
            ))}
          </div>

          <Panel className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-tatu-border">
                  <th className={thClass}>Name</th>
                  <th className={thClass}>Category</th>
                  <th className={thClass}>Severity</th>
                  <th className={thClass}>Mode</th>
                  <th className={thClass}>Action</th>
                  <th className={thClass}>Format</th>
                  <th className={thClass}>Source</th>
                  <th className={thClass}>Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((rule) => (
                  <tr
                    key={rule.id}
                    className="border-b border-tatu-border/50 hover:bg-tatu-surface-alt/50 cursor-pointer"
                    onClick={() => navigate(`/rules/${rule.id}`)}
                  >
                    <td className="py-2.5 px-3 text-tatu-text font-medium">{rule.name}</td>
                    <td className="py-2.5 px-3 text-tatu-text-muted">{rule.category}</td>
                    <td className="py-2.5 px-3">
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase ${
                          rule.mode === "strict"
                            ? "bg-tatu-critical-dim text-tatu-critical"
                            : "bg-tatu-info-dim text-tatu-info"
                        }`}
                      >
                        {rule.mode}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-tatu-text-muted uppercase text-[10px] font-semibold tracking-wider">
                      {rule.action}
                    </td>
                    <td className="py-2.5 px-3 text-tatu-text-muted uppercase text-[10px] font-semibold tracking-wider">
                      {rule.format}
                    </td>
                    <td className="py-2.5 px-3 text-tatu-text-muted">{rule.source}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase ${
                          rule.enabled
                            ? "bg-tatu-accent/15 text-tatu-accent"
                            : "bg-tatu-surface-alt text-tatu-text-dim"
                        }`}
                      >
                        {rule.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </td>
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-6 px-3 text-center text-tatu-text-dim text-xs">
                      No rules matching your search
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </Panel>
        </>
      )}
    </div>
  );
}
