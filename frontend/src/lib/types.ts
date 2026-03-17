export interface Event {
  id: string;
  timestamp: string;
  hook_name: string;
  hook_event: string;
  severity: "critical" | "warning" | "info";
  status: "blocked" | "warning" | "allowed" | "clean" | "audit_block";
  message: string;
  developer: string;
  repository: string;
  session_id: string;
  tool_name: string | null;
  metadata_: Record<string, unknown>;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

export interface OverviewStats {
  total_events: number;
  total_blocks: number;
  active_sessions: number;
  secrets_caught: number;
  block_rate: number;
}

export interface TimelineBucket {
  hour: string;
  events: number;
  blocks: number;
}

export interface RuleWithStats {
  id: string;
  name: string;
  category: string;
  hook_event: string;
  matcher: string;
  enabled: boolean;
  compliance_mappings: string[];
  triggers: number;
  blocks: number;
  block_rate: string;
}

export interface DeveloperStats {
  name: string;
  sessions: number;
  blocks: number;
  risk: "high" | "low";
}

export interface ComplianceFramework {
  framework: string;
  controls: number;
  covered: number;
  evidenced: number;
  status: string;
  percentage: number;
}

export interface ComplianceMapping {
  hook: string;
  maps: string;
}

export interface ComplianceResponse {
  frameworks: ComplianceFramework[];
  mappings: ComplianceMapping[];
}

export interface Rule {
  id: string;
  name: string;
  format: "yaml" | "yara";
  content: string;
  source: "builtin" | "custom";
  enabled: boolean;
  category: string;
  severity: "critical" | "warning" | "info";
  mode: "audit" | "strict";
  action: "block" | "warn" | "log";
  hook_event: string;
  matcher: string;
  version_added: number;
}

export interface ApiKeyResponse {
  id: string;
  label: string;
  created_at: string;
  last_used_at: string | null;
  active: boolean;
}

export interface ApiKeyCreateResponse {
  id: string;
  label: string;
  api_key: string;
}

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: "admin" | "editor" | "viewer";
}
