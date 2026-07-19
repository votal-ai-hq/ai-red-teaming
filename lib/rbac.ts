/**
 * Role-Based Access Control.
 * Defines which roles can access which endpoints.
 */

export type Role = "admin" | "viewer" | "auditor";

interface RoutePermission {
  method: string;
  pattern: RegExp;
  roles: Role[];
}

const PERMISSIONS: RoutePermission[] = [
  // Runs
  { method: "POST", pattern: /^\/api\/run$/, roles: ["admin"] },
  { method: "DELETE", pattern: /^\/api\/run\//, roles: ["admin"] },
  { method: "GET", pattern: /^\/api\/run\//, roles: ["admin", "viewer"] },
  { method: "GET", pattern: /^\/api\/runs$/, roles: ["admin", "viewer"] },

  // Reports
  { method: "GET", pattern: /^\/api\/reports$/, roles: ["admin", "viewer"] },
  {
    method: "GET",
    pattern: /^\/api\/reports-meta/,
    roles: ["admin", "viewer"],
  },
  { method: "GET", pattern: /^\/api\/report\//, roles: ["admin", "viewer"] },
  {
    method: "GET",
    pattern: /^\/api\/report-csv\//,
    roles: ["admin", "viewer"],
  },

  // Compliance
  {
    method: "GET",
    pattern: /^\/api\/compliance-frameworks$/,
    roles: ["admin", "viewer", "auditor"],
  },
  {
    method: "GET",
    pattern: /^\/api\/compliance-status$/,
    roles: ["admin", "viewer", "auditor"],
  },
  {
    // Deterministic, no-LLM framework mapping shown by default in the
    // Compliance tab. Read-only, so available to every read role.
    method: "GET",
    pattern: /^\/api\/compliance-static$/,
    roles: ["admin", "viewer", "auditor"],
  },
  {
    method: "POST",
    pattern: /^\/api\/owasp-analyze$/,
    roles: ["admin", "auditor"],
  },
  {
    method: "POST",
    pattern: /^\/api\/risk-analyze$/,
    roles: ["admin", "auditor"],
  },

  // LiteLLM Guardrails Reports
  {
    method: "GET",
    pattern: /^\/api\/litellm-reports$/,
    roles: ["admin", "viewer"],
  },
  {
    method: "GET",
    pattern: /^\/api\/litellm-report\//,
    roles: ["admin", "viewer"],
  },
  {
    method: "POST",
    pattern: /^\/api\/litellm-report-upload$/,
    roles: ["admin"],
  },

  // Datasets & Evaluations
  { method: "GET", pattern: /^\/api\/datasets$/, roles: ["admin", "viewer"] },
  {
    method: "POST",
    pattern: /^\/api\/datasets\/generate$/,
    roles: ["admin"],
  },
  {
    method: "POST",
    pattern: /^\/api\/datasets\/promote$/,
    roles: ["admin"],
  },
  { method: "GET", pattern: /^\/api\/eval-runs$/, roles: ["admin", "viewer"] },

  // Audit log
  { method: "GET", pattern: /^\/api\/audit-log/, roles: ["admin", "auditor"] },

  // Policy management
  { method: "GET", pattern: /^\/api\/policies$/, roles: ["admin", "viewer"] },
  { method: "POST", pattern: /^\/api\/policy-upload$/, roles: ["admin"] },
];

/**
 * Check if a role has permission to access a given endpoint.
 * Returns true if allowed, false if denied.
 * If no matching rule is found, defaults to deny.
 */
export function checkPermission(
  method: string,
  pathname: string,
  role: Role,
): boolean {
  for (const perm of PERMISSIONS) {
    if (perm.method === method && perm.pattern.test(pathname)) {
      return perm.roles.includes(role);
    }
  }
  // No matching rule — deny by default
  return false;
}
