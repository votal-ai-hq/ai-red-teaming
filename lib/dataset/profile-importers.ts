/**
 * Fill an AppProfile from an artifact a developer already has. Three sources
 * (the intake "option 2" formats):
 *   - system-prompt text  -> systemPrompt + heuristically-extracted businessRules
 *   - MCP tool manifest    -> tools (+ sensitivity) from a tools/list result
 *   - OpenAPI / Swagger    -> tools from operations, roles from security schemes
 *   - policy document      -> structured policies (name + criteria) from markdown/
 *                            text/JSON (the DeepEval "generate from docs" analogue)
 *
 * All pure + I/O-free. Each returns a PARTIAL profile (no name yet) so the
 * caller/wizard can name it and merge with hand edits (see mergeProfiles).
 * Parsers are lenient: malformed input yields as much as can be salvaged, not
 * an exception, so a paste never hard-fails the intake flow.
 */
import type { AppProfile, Policy, ProfileTool } from "./app-profile.js";

export type ImportFormat =
  | "system-prompt"
  | "mcp-manifest"
  | "openapi"
  | "policy-doc";

/** Words that suggest a tool mutates state / exfiltrates / needs privilege. */
const SENSITIVE_RE =
  /\b(delete|remove|drop|write|update|create|insert|modify|patch|send|email|mail|post|publish|transfer|pay|payment|refund|charge|withdraw|admin|grant|revoke|role|permission|exec|execute|run|shell|command|deploy|config|secret|credential|token|password|key|export|download|upload|purge|wipe)\b/i;

function toolIsSensitive(name: string, description = ""): boolean {
  // Split identifier separators (snake_case, camelCase, dots) so word
  // boundaries land — otherwise "delete_file" hides "delete" behind a "_",
  // which is a word char to \b.
  const words = `${name} ${description}`
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[._-]+/g, " ");
  return SENSITIVE_RE.test(words);
}

function cleanTools(raw: Array<{ name: string; description?: string }>): ProfileTool[] {
  const out: ProfileTool[] = [];
  const seen = new Set<string>();
  for (const t of raw) {
    const name = (t.name ?? "").trim();
    if (!name || seen.has(name.toLowerCase())) continue;
    seen.add(name.toLowerCase());
    const description = (t.description ?? "").trim().replace(/\s+/g, " ");
    const tool: ProfileTool = { name };
    if (description) tool.description = description.slice(0, 200);
    if (toolIsSensitive(name, description)) tool.sensitive = true;
    out.push(tool);
  }
  return out;
}

/**
 * Extract likely business rules from a system prompt: lines that read as
 * imperative constraints (never/always/must/only/do not/refuse/don't …) or
 * bulleted list items. Best-effort — meant to seed the wizard, not be exact.
 */
export function extractBusinessRules(systemPrompt: string): string[] {
  const RULE_RE =
    /\b(never|always|must|must not|do not|don't|refuse|only|ensure|forbidden|not allowed|prohibited|require[ds]?|shall|should not)\b/i;
  const rules: string[] = [];
  const seen = new Set<string>();
  for (const rawLine of systemPrompt.split(/\r?\n/)) {
    // Strip any leading bullet / number marker, then keep the line only if it
    // reads as a constraint. Plain bullets without rule language are too noisy.
    const line = rawLine.trim().replace(/^([-*•]|\d+[.)])\s+/, "").trim();
    if (line.length < 8 || line.length > 300) continue;
    if (!RULE_RE.test(line)) continue;
    const key = line.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    rules.push(line);
    if (rules.length >= 40) break;
  }
  return rules;
}

export function parseSystemPrompt(text: string): Partial<AppProfile> {
  const systemPrompt = text.trim();
  const profile: Partial<AppProfile> = { source: "system-prompt" };
  if (systemPrompt) {
    profile.systemPrompt = systemPrompt;
    const rules = extractBusinessRules(systemPrompt);
    if (rules.length) profile.businessRules = rules;
  }
  return profile;
}

/**
 * Parse an MCP tools/list result. Accepts `{ tools: [...] }`, `{ result: {
 * tools: [...] } }`, or a bare array. Each tool: { name, description }.
 */
export function parseMcpManifest(json: unknown): Partial<AppProfile> {
  const container =
    (json as { result?: { tools?: unknown } })?.result ?? json;
  const rawTools =
    (container as { tools?: unknown })?.tools ??
    (Array.isArray(json) ? json : []);
  const list = Array.isArray(rawTools) ? rawTools : [];
  const tools = cleanTools(
    list
      .filter((t): t is Record<string, unknown> => !!t && typeof t === "object")
      .map((t) => ({
        name: String(t.name ?? ""),
        description: String(t.description ?? ""),
      })),
  );
  const profile: Partial<AppProfile> = { source: "mcp-manifest" };
  if (tools.length) profile.tools = tools;
  const serverName = (container as { serverInfo?: { name?: unknown } })
    ?.serverInfo?.name;
  if (typeof serverName === "string" && serverName.trim()) {
    profile.description = `MCP server "${serverName.trim()}"`;
  }
  return profile;
}

const HTTP_METHODS = ["get", "put", "post", "delete", "patch", "head", "options"];
const MUTATING = new Set(["put", "post", "delete", "patch"]);

/**
 * Parse an OpenAPI / Swagger document (v2 or v3). Operations become tools
 * (operationId, else METHOD /path); mutating verbs are marked sensitive.
 * Security-scheme names and OAuth2 scopes become roles.
 */
export function parseOpenApi(json: unknown): Partial<AppProfile> {
  const doc = (json ?? {}) as Record<string, unknown>;
  const paths = (doc.paths ?? {}) as Record<string, unknown>;
  const rawTools: Array<{ name: string; description?: string; sensitive?: boolean }> =
    [];

  for (const [path, pathItemRaw] of Object.entries(paths)) {
    if (!pathItemRaw || typeof pathItemRaw !== "object") continue;
    const pathItem = pathItemRaw as Record<string, unknown>;
    for (const method of HTTP_METHODS) {
      const opRaw = pathItem[method];
      if (!opRaw || typeof opRaw !== "object") continue;
      const op = opRaw as Record<string, unknown>;
      const opId = typeof op.operationId === "string" ? op.operationId.trim() : "";
      const name = opId || `${method.toUpperCase()} ${path}`;
      const description = String(op.summary ?? op.description ?? "")
        .trim()
        .replace(/\s+/g, " ");
      const forcedSensitive =
        MUTATING.has(method) || toolIsSensitive(name, description);
      rawTools.push({
        name,
        description,
        sensitive: forcedSensitive || undefined,
      });
    }
  }

  // cleanTools recomputes sensitivity from keywords; OR in the verb-based flag.
  const tools = cleanTools(rawTools).map((t) => {
    const orig = rawTools.find((r) => r.name === t.name);
    return orig?.sensitive ? { ...t, sensitive: true } : t;
  });

  const roles = collectOpenApiRoles(doc);

  const profile: Partial<AppProfile> = { source: "openapi" };
  const info = doc.info as { title?: unknown; description?: unknown } | undefined;
  const title = typeof info?.title === "string" ? info.title.trim() : "";
  const infoDesc =
    typeof info?.description === "string" ? info.description.trim() : "";
  if (title || infoDesc) {
    profile.description = [title, infoDesc].filter(Boolean).join(" — ").slice(0, 2000);
  }
  if (tools.length) profile.tools = tools;
  if (roles.length) profile.roles = roles;
  return profile;
}

function collectOpenApiRoles(doc: Record<string, unknown>): string[] {
  const roles = new Set<string>();
  // OpenAPI v3: components.securitySchemes; v2: securityDefinitions.
  const schemes =
    ((doc.components as { securitySchemes?: unknown })?.securitySchemes as
      | Record<string, unknown>
      | undefined) ??
    (doc.securityDefinitions as Record<string, unknown> | undefined) ??
    {};
  for (const [schemeName, schemeRaw] of Object.entries(schemes)) {
    roles.add(schemeName);
    if (!schemeRaw || typeof schemeRaw !== "object") continue;
    const scheme = schemeRaw as Record<string, unknown>;
    // OAuth2 scopes (v2 flat, or v3 nested under flows.*.scopes).
    const scopeSources: unknown[] = [scheme.scopes];
    const flows = scheme.flows as Record<string, unknown> | undefined;
    if (flows) {
      for (const flow of Object.values(flows)) {
        if (flow && typeof flow === "object") {
          scopeSources.push((flow as Record<string, unknown>).scopes);
        }
      }
    }
    for (const src of scopeSources) {
      if (src && typeof src === "object") {
        for (const scope of Object.keys(src as Record<string, unknown>)) {
          roles.add(scope);
        }
      }
    }
  }
  return Array.from(roles).slice(0, 20);
}

/** A markdown/text heading, e.g. "## No cross-tenant access" or "1. Refunds". */
const HEADING_RE = /^(?:#{1,6}\s+|\d+[.)]\s+|[-*•]\s+)(.+)$/;

/**
 * Parse a policy document into structured policies (name + criteria).
 *
 * Two shapes are accepted:
 *   - JSON: an array of {name, criteria, types?} or {policies:[...]} — passed
 *     straight through (validated downstream).
 *   - Markdown/plain text: each heading / list item becomes a policy `name` and
 *     the prose beneath it (up to the next heading) becomes the `criteria`. A
 *     "Name: criteria" line on its own also works. This is the DeepEval
 *     "generate from docs" analogue — the doc IS the policy source.
 */
export function parsePolicyDoc(content: string): Partial<AppProfile> {
  const trimmed = content.trim();

  // JSON path: array of policies or { policies: [...] }.
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const json = JSON.parse(trimmed) as unknown;
      const arr = Array.isArray(json)
        ? json
        : ((json as { policies?: unknown })?.policies ?? []);
      if (Array.isArray(arr)) {
        return { policies: arr as Policy[], source: "policy-doc" };
      }
    } catch {
      // fall through to text parsing
    }
  }

  const policies: Policy[] = [];
  const pushPolicy = (name: string, criteria: string) => {
    const n = name.trim().replace(/[:.]$/, "").slice(0, 120);
    const c = criteria.trim().replace(/\s+/g, " ").slice(0, 400);
    if (n && c) policies.push({ name: n, criteria: c });
  };

  const lines = trimmed.split(/\r?\n/);
  let currentName = "";
  let buffer: string[] = [];
  const flush = () => {
    if (currentName) pushPolicy(currentName, buffer.join(" "));
    buffer = [];
  };

  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;

    // "Name: criteria" on one line is a self-contained policy.
    const inline = line.match(/^([A-Z][\w &/-]{2,60}?):\s+(.{8,})$/);
    const heading = line.match(HEADING_RE);

    if (inline && !heading) {
      flush();
      currentName = "";
      pushPolicy(inline[1], inline[2]);
    } else if (heading) {
      flush();
      currentName = heading[1];
    } else if (currentName) {
      buffer.push(line);
    }
  }
  flush();

  return policies.length ? { policies, source: "policy-doc" } : { source: "policy-doc" };
}

/** Dispatch to the right parser. Throws only on JSON parse failure for JSON formats. */
export function importProfile(
  format: ImportFormat,
  content: string,
): Partial<AppProfile> {
  if (format === "system-prompt") return parseSystemPrompt(content);
  if (format === "policy-doc") return parsePolicyDoc(content);
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    throw new Error(
      `content is not valid JSON — ${format} import expects a JSON document`,
    );
  }
  return format === "mcp-manifest" ? parseMcpManifest(json) : parseOpenApi(json);
}
