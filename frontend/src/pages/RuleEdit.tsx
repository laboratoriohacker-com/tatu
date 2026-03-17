import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import type { Rule } from "../lib/types";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";
import { SeverityBadge } from "../components/SeverityBadge";

export function RuleEdit() {
  const { ruleId } = useParams<{ ruleId: string }>();
  const navigate = useNavigate();
  const { data: rule, loading, refetch } = useApi<Rule>(
    () => api.getRule(ruleId!) as Promise<Rule>,
    [ruleId],
  );

  const [name, setName] = useState("");
  const [content, setContent] = useState("");
  const [mode, setMode] = useState<"audit" | "strict">("audit");
  const [action, setAction] = useState<"block" | "warn" | "log">("block");
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const isBuiltin = rule?.source === "builtin";

  useEffect(() => {
    if (rule) {
      setName(rule.name);
      setContent(rule.content);
      setMode(rule.mode);
      setAction(rule.action);
      setEnabled(rule.enabled);
      setError(null);
      setSuccess(false);
    }
  }, [rule]);

  const handleSave = async () => {
    if (!rule) return;
    setSaving(true);
    setError(null);
    setSuccess(false);
    try {
      const body: Record<string, unknown> = { mode, action, enabled };
      if (!isBuiltin) {
        body.name = name;
        body.content = content;
      }
      await api.updateRule(rule.id, body);
      setSuccess(true);
      refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const handleClone = async () => {
    if (!rule) return;
    setSaving(true);
    setError(null);
    try {
      await api.cloneRule(rule.id);
      refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Clone failed");
    } finally {
      setSaving(false);
    }
  };

  const toggleClass = (active: boolean) =>
    `px-3 py-1.5 rounded text-[11px] font-semibold uppercase tracking-wider border transition-colors ${
      active
        ? "bg-tatu-accent/20 border-tatu-accent text-tatu-accent"
        : "bg-tatu-surface border-tatu-border text-tatu-text-muted hover:border-tatu-border-hover"
    }`;

  if (loading || !rule) {
    return (
      <div>
        <PageHeader title="Rule" />
        <p className="text-tatu-text-muted text-sm">Loading...</p>
      </div>
    );
  }

  return (
    <div>
      {/* Header with back link */}
      <div className="flex items-center gap-3 mb-5">
        <button
          onClick={() => navigate("/rules")}
          className="text-tatu-text-dim hover:text-tatu-accent text-xs transition-colors"
        >
          Rules
        </button>
        <span className="text-tatu-text-dim text-xs">/</span>
        <span className="text-tatu-text text-xs font-medium">{rule.id}</span>
      </div>

      {/* Rule name */}
      <div className="mb-5">
        {isBuiltin ? (
          <h1 className="text-lg font-bold text-tatu-text">{rule.name}</h1>
        ) : (
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="text-lg font-bold text-tatu-text bg-transparent border-b border-tatu-border/50 focus:border-tatu-accent outline-none pb-1 w-full max-w-lg"
          />
        )}
        <div className="flex items-center gap-2 mt-2">
          <SeverityBadge severity={rule.severity} />
          <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-tatu-surface-alt text-tatu-text-dim">
            {rule.format}
          </span>
          <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-tatu-surface-alt text-tatu-text-dim">
            {rule.source}
          </span>
          <span className="text-[10px] text-tatu-text-dim">
            {rule.hook_event} · {rule.matcher}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Controls */}
        <div className="space-y-4">
          <Panel>
            {/* Enable/Disable */}
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs text-tatu-text-muted uppercase tracking-wider">Status</span>
              <button
                onClick={() => setEnabled(!enabled)}
                className={`px-3 py-1 rounded text-[10px] font-semibold tracking-wider uppercase ${
                  enabled
                    ? "bg-tatu-accent/15 text-tatu-accent"
                    : "bg-tatu-surface-alt text-tatu-text-dim"
                }`}
              >
                {enabled ? "Enabled" : "Disabled"}
              </button>
            </div>

            {/* Mode */}
            <div className="mb-4">
              <label className="text-xs text-tatu-text-muted uppercase tracking-wider block mb-2">
                Mode
              </label>
              <div className="flex gap-2">
                <button onClick={() => setMode("audit")} className={toggleClass(mode === "audit")}>
                  Audit
                </button>
                <button onClick={() => setMode("strict")} className={toggleClass(mode === "strict")}>
                  Strict
                </button>
              </div>
            </div>

            {/* Action */}
            <div className="mb-4">
              <label className="text-xs text-tatu-text-muted uppercase tracking-wider block mb-2">
                Action
              </label>
              <div className="flex gap-2">
                {(["block", "warn", "log"] as const).map((a) => (
                  <button key={a} onClick={() => setAction(a)} className={toggleClass(action === a)}>
                    {a}
                  </button>
                ))}
              </div>
            </div>

            {/* Metadata */}
            <div className="space-y-2 pt-3 border-t border-tatu-border">
              <div className="flex justify-between text-[11px]">
                <span className="text-tatu-text-dim">Category</span>
                <span className="text-tatu-text-muted">{rule.category}</span>
              </div>
              <div className="flex justify-between text-[11px]">
                <span className="text-tatu-text-dim">Hook Event</span>
                <span className="text-tatu-text-muted">{rule.hook_event}</span>
              </div>
              <div className="flex justify-between text-[11px]">
                <span className="text-tatu-text-dim">Matcher</span>
                <span className="text-tatu-text-muted font-mono">{rule.matcher}</span>
              </div>
              <div className="flex justify-between text-[11px]">
                <span className="text-tatu-text-dim">Version</span>
                <span className="text-tatu-text-muted">{rule.version_added}</span>
              </div>
            </div>
          </Panel>

          {/* Actions */}
          <div className="space-y-2">
            {error && <p className="text-xs text-tatu-critical">{error}</p>}
            {success && <p className="text-xs text-tatu-accent">Saved successfully</p>}
            <button
              onClick={handleSave}
              disabled={saving}
              className="w-full px-4 py-2.5 rounded text-xs font-semibold bg-tatu-accent text-tatu-bg hover:bg-tatu-accent/90 disabled:opacity-50 transition-colors"
            >
              {saving ? "Saving..." : "Save Changes"}
            </button>
            {isBuiltin && (
              <button
                onClick={handleClone}
                disabled={saving}
                className="w-full px-4 py-2.5 rounded text-xs font-semibold border border-tatu-border text-tatu-text-muted hover:border-tatu-border-hover disabled:opacity-50 transition-colors"
              >
                Clone to Custom
              </button>
            )}
          </div>
        </div>

        {/* Right: Content editor */}
        <div className="lg:col-span-2">
          <Panel className="h-full">
            <div className="flex items-center justify-between mb-3">
              <label className="text-xs text-tatu-text-muted uppercase tracking-wider">
                {rule.format === "yara" ? "YARA Rule" : "YAML Template"}
              </label>
              {isBuiltin && (
                <span className="text-[10px] text-tatu-text-dim">
                  Read-only — clone to custom to edit
                </span>
              )}
            </div>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              readOnly={isBuiltin}
              className={`w-full bg-tatu-bg border border-tatu-border rounded-lg p-3 text-xs text-tatu-text font-mono resize-y outline-none focus:border-tatu-accent ${
                isBuiltin ? "opacity-70 cursor-not-allowed" : ""
              }`}
              style={{ minHeight: "500px" }}
              spellCheck={false}
            />
          </Panel>
        </div>
      </div>
    </div>
  );
}
