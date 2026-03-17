import { useState } from "react";
import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import type { ApiKeyResponse, ApiKeyCreateResponse } from "../lib/types";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";

interface UserRecord {
  id: string;
  email: string;
  name: string;
  role: "admin" | "editor" | "viewer";
  active: boolean;
  created_at: string;
}

interface SettingsProps {
  userRole?: "admin" | "editor" | "viewer";
}

export function Settings({ userRole }: SettingsProps) {
  const { data, loading, refetch } = useApi<ApiKeyResponse[]>(
    () => api.getApiKeys() as Promise<ApiKeyResponse[]>,
    [],
  );
  const [label, setLabel] = useState("");
  const [creating, setCreating] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleCreate = async () => {
    if (!label.trim()) return;
    setCreating(true);
    setError(null);
    setNewKey(null);
    try {
      const result = (await api.createApiKey(label.trim())) as ApiKeyCreateResponse;
      setNewKey(result.api_key);
      setLabel("");
      refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create key");
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (id: string) => {
    try {
      await api.revokeApiKey(id);
      refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke key");
    }
  };

  const handleCopy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const keys = data ?? [];

  return (
    <div>
      <PageHeader title="Settings" />

      <h2 className="text-sm font-semibold text-tatu-text mb-4">API Keys</h2>
      <p className="text-xs text-tatu-text-muted mb-5">
        API keys authenticate <code className="text-tatu-accent">tatu-hook</code> to send events and sync rules.
        Create a key here and use it with <code className="text-tatu-accent">tatu-hook init --api-key</code>.
      </p>

      {/* Create new key */}
      <Panel className="mb-5">
        <div className="flex gap-3 items-end">
          <div className="flex-1 max-w-xs">
            <label className="text-[10px] text-tatu-text-dim uppercase tracking-wider block mb-1.5">
              Label
            </label>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              placeholder="e.g. production-hooks"
              className="w-full bg-tatu-bg border border-tatu-border rounded px-3 py-2 text-xs text-tatu-text placeholder:text-tatu-text-dim outline-none focus:border-tatu-accent transition-colors"
            />
          </div>
          <button
            onClick={handleCreate}
            disabled={creating || !label.trim()}
            className="px-4 py-2 rounded text-xs font-semibold bg-tatu-accent text-tatu-bg hover:bg-tatu-accent/90 disabled:opacity-50 transition-colors"
          >
            {creating ? "Creating..." : "Create API Key"}
          </button>
        </div>

        {error && <p className="text-xs text-tatu-critical mt-3">{error}</p>}

        {newKey && (
          <div className="mt-4 p-3 bg-tatu-bg border border-tatu-accent/30 rounded-lg">
            <p className="text-[10px] text-tatu-accent uppercase tracking-wider mb-2 font-semibold">
              New API Key — copy it now, it won't be shown again
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs text-tatu-text font-mono bg-tatu-surface px-3 py-2 rounded border border-tatu-border select-all break-all">
                {newKey}
              </code>
              <button
                onClick={() => handleCopy(newKey)}
                className="px-3 py-2 rounded text-xs font-semibold border border-tatu-border text-tatu-text-muted hover:border-tatu-accent hover:text-tatu-accent transition-colors whitespace-nowrap"
              >
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
          </div>
        )}
      </Panel>

      {/* Existing keys */}
      {loading && <p className="text-tatu-text-muted text-sm">Loading...</p>}

      {!loading && (
        <Panel className="overflow-x-auto mb-10">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-tatu-border">
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Label
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Created
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Last Used
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.id} className="border-b border-tatu-border/50 hover:bg-tatu-surface-alt/50">
                  <td className="py-2.5 px-3 text-tatu-text font-medium">{key.label}</td>
                  <td className="py-2.5 px-3 text-tatu-text-muted">
                    {new Date(key.created_at).toLocaleDateString()}
                  </td>
                  <td className="py-2.5 px-3 text-tatu-text-muted">
                    {key.last_used_at
                      ? new Date(key.last_used_at).toLocaleDateString()
                      : "Never"}
                  </td>
                  <td className="py-2.5 px-3">
                    <button
                      onClick={() => handleRevoke(key.id)}
                      className="text-[10px] font-semibold uppercase tracking-wider text-tatu-critical hover:text-tatu-critical/80 transition-colors"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
              {keys.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-6 px-3 text-center text-tatu-text-dim text-xs">
                    No API keys yet. Create one to use with tatu-hook.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </Panel>
      )}

      {/* Users section — visible to admin and editor only */}
      {(userRole === "admin" || userRole === "editor") && (
        <UsersSection userRole={userRole} />
      )}
    </div>
  );
}

function UsersSection({ userRole }: { userRole: "admin" | "editor" }) {
  const { data: users, loading, refetch } = useApi<UserRecord[]>(
    () => api.getUsers() as Promise<UserRecord[]>,
    [],
  );

  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteName, setInviteName] = useState("");
  const [inviteRole, setInviteRole] = useState("viewer");
  const [inviting, setInviting] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [inviteSuccess, setInviteSuccess] = useState(false);

  const handleInvite = async () => {
    if (!inviteEmail.trim() || !inviteName.trim()) return;
    setInviting(true);
    setInviteError(null);
    setInviteSuccess(false);
    try {
      await api.inviteUser({ email: inviteEmail.trim(), name: inviteName.trim(), role: inviteRole });
      setInviteEmail("");
      setInviteName("");
      setInviteRole("viewer");
      setInviteSuccess(true);
      refetch();
    } catch (err) {
      setInviteError(err instanceof Error ? err.message : "Failed to invite user");
    } finally {
      setInviting(false);
    }
  };

  const handleRoleChange = async (id: string, role: string) => {
    try {
      await api.updateUser(id, { role });
      refetch();
    } catch {
      // ignore
    }
  };

  const handleDeactivate = async (id: string) => {
    try {
      await api.deactivateUser(id);
      refetch();
    } catch {
      // ignore
    }
  };

  const userList = users ?? [];

  return (
    <div>
      <h2 className="text-sm font-semibold text-tatu-text mb-4">Users</h2>
      <p className="text-xs text-tatu-text-muted mb-5">
        Manage team members and their access levels.
      </p>

      {userRole === "admin" && (
        <Panel className="mb-5">
          <p className="text-[10px] text-tatu-text-dim uppercase tracking-wider mb-3 font-semibold">
            Invite User
          </p>
          <div className="flex gap-3 items-end flex-wrap">
            <div className="flex-1 min-w-[160px]">
              <label className="text-[10px] text-tatu-text-dim uppercase tracking-wider block mb-1.5">
                Name
              </label>
              <input
                type="text"
                value={inviteName}
                onChange={(e) => setInviteName(e.target.value)}
                placeholder="Full name"
                className="w-full bg-tatu-bg border border-tatu-border rounded px-3 py-2 text-xs text-tatu-text placeholder:text-tatu-text-dim outline-none focus:border-tatu-accent transition-colors"
              />
            </div>
            <div className="flex-1 min-w-[200px]">
              <label className="text-[10px] text-tatu-text-dim uppercase tracking-wider block mb-1.5">
                Email
              </label>
              <input
                type="email"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                placeholder="user@example.com"
                className="w-full bg-tatu-bg border border-tatu-border rounded px-3 py-2 text-xs text-tatu-text placeholder:text-tatu-text-dim outline-none focus:border-tatu-accent transition-colors"
              />
            </div>
            <div>
              <label className="text-[10px] text-tatu-text-dim uppercase tracking-wider block mb-1.5">
                Role
              </label>
              <select
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value)}
                className="bg-tatu-bg border border-tatu-border rounded px-3 py-2 text-xs text-tatu-text outline-none focus:border-tatu-accent transition-colors"
              >
                <option value="viewer">Viewer</option>
                <option value="editor">Editor</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <button
              onClick={handleInvite}
              disabled={inviting || !inviteEmail.trim() || !inviteName.trim()}
              className="px-4 py-2 rounded text-xs font-semibold bg-tatu-accent text-tatu-bg hover:bg-tatu-accent/90 disabled:opacity-50 transition-colors"
            >
              {inviting ? "Inviting..." : "Send Invite"}
            </button>
          </div>
          {inviteError && <p className="text-xs text-tatu-critical mt-3">{inviteError}</p>}
          {inviteSuccess && (
            <p className="text-xs text-tatu-accent mt-3">Invitation sent successfully.</p>
          )}
        </Panel>
      )}

      {loading && <p className="text-tatu-text-muted text-sm">Loading...</p>}

      {!loading && (
        <Panel className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-tatu-border">
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">Name</th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">Email</th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">Role</th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">Status</th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">Created</th>
                {userRole === "admin" && (
                  <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">Actions</th>
                )}
              </tr>
            </thead>
            <tbody>
              {userList.map((u) => (
                <tr key={u.id} className="border-b border-tatu-border/50 hover:bg-tatu-surface-alt/50">
                  <td className="py-2.5 px-3 text-tatu-text font-medium">{u.name}</td>
                  <td className="py-2.5 px-3 text-tatu-text-muted">{u.email}</td>
                  <td className="py-2.5 px-3">
                    {userRole === "admin" ? (
                      <select
                        value={u.role}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                        className="bg-tatu-bg border border-tatu-border rounded px-2 py-1 text-xs text-tatu-text outline-none focus:border-tatu-accent transition-colors"
                      >
                        <option value="viewer">Viewer</option>
                        <option value="editor">Editor</option>
                        <option value="admin">Admin</option>
                      </select>
                    ) : (
                      <span className="capitalize text-tatu-text-muted">{u.role}</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className={`text-[10px] font-semibold uppercase tracking-wider ${u.active ? "text-tatu-accent" : "text-tatu-text-dim"}`}>
                      {u.active ? "Active" : "Inactive"}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-tatu-text-muted">
                    {new Date(u.created_at).toLocaleDateString()}
                  </td>
                  {userRole === "admin" && (
                    <td className="py-2.5 px-3">
                      {u.active && (
                        <button
                          onClick={() => handleDeactivate(u.id)}
                          className="text-[10px] font-semibold uppercase tracking-wider text-tatu-critical hover:text-tatu-critical/80 transition-colors"
                        >
                          Deactivate
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
              {userList.length === 0 && (
                <tr>
                  <td colSpan={userRole === "admin" ? 6 : 5} className="py-6 px-3 text-center text-tatu-text-dim text-xs">
                    No users found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}
