/**
 * MCP metadata / tool-poisoning scanners.
 *
 * Grounded in primary-source research (Invariant Labs "Tool Poisoning Attacks",
 * CyberArk "Full-Schema Poisoning / Poison Everywhere", OWASP MCP03:2025,
 * modelcontextprotocol.io security best-practices, CoSAI/OASIS MCP whitepaper):
 *
 * - Tool poisoning: injection directives live not just in descriptions but in
 *   EVERY schema field — parameter names, defaults, required arrays, and
 *   non-standard/extra keys ("Full-Schema Poisoning"). The LLM reads all of it
 *   from tools/list even when the tool is never invoked, and users see a
 *   simplified view (visibility asymmetry). High-signal markers: hidden tags
 *   (<IMPORTANT>), file-path exfiltration targets (~/.ssh/id_rsa,
 *   ~/.cursor/mcp.json), concealment directives ("do not tell the user"), and
 *   imperative "before using this tool" instructions.
 * - Tool shadowing / namespace collision: a tool description that issues
 *   directives about a DIFFERENT tool (e.g. redirect send_email to an attacker
 *   address), duplicate tool names, and cross-tool redirection.
 *
 * Kept dependency-free and pure so it is unit-testable in isolation.
 */

export interface McpToolLike {
  name?: string;
  description?: string;
  inputSchema?: unknown;
}
export interface McpDiscoveryLike {
  tools?: McpToolLike[];
  prompts?: { name?: string; description?: string }[];
  resources?: { uri?: string; name?: string; description?: string }[];
  instructions?: string;
}

// ── Research-backed signal sets ──
/** Imperative directives that steer the model ("before using this tool, …"). */
const IMPERATIVE =
  /\b(ignore (all |any )?(previous|prior)|before (using|calling|invoking) this tool|you must (first|always)|instead of|first,? (read|call|fetch|send|open)|as an ai|new instructions?)\b/i;
/** Filesystem exfiltration targets seen in the canonical PoCs. */
const FILE_PATH_EXFIL =
  /(~\/\.ssh|id_rsa(\.pub)?|\.cursor\/mcp\.json|\/etc\/passwd|\.aws\/credentials|\.env\b|private[_-]?key|\.git-credentials)/i;
/** Concealment / "don't tell the user" directives. */
const CONCEAL =
  /\b(do not (tell|inform|notify|reveal|mention)|don't (tell|notify|mention|reveal)|without (telling|informing|notifying)|silently|secretly|conceal|hide (this|the|it))\b/i;
/** Hidden instruction tags (<IMPORTANT>, <system>, …). */
const HIDDEN_TAG = /<\s*\/?\s*(important|secret|system|instructions?|admin)\s*>/i;
/** Exfiltration verbs. */
const EXFIL_VERB = /\b(send|email|post|exfiltrat\w*|upload|forward|transmit|leak)\b/i;
/** External destinations (excludes RFC example/reserved hosts). */
const EXTERNAL_ADDR =
  /([a-z0-9._%+-]+@(?!example\.(?:com|test|org)\b)[a-z0-9.-]+\.[a-z]{2,}|https?:\/\/(?!localhost|127\.0\.0\.1)[^\s"']+|\+\d{7,})/i;
/** JSON-Schema keys that are legitimate; anything else at property level is "extra". */
const STANDARD_SCHEMA_KEYS = new Set([
  "type", "description", "properties", "required", "items", "enum", "default",
  "format", "title", "minimum", "maximum", "minLength", "maxLength", "pattern",
  "additionalProperties", "anyOf", "allOf", "oneOf", "$ref", "$schema",
  "examples", "const", "nullable", "definitions", "$defs", "propertyNames",
  "minItems", "maxItems", "uniqueItems", "multipleOf", "not",
]);

export interface PoisonFinding {
  tool: string;
  field: string;
  signal: string;
  snippet: string;
}

function snippet(text: string): string {
  return text.slice(0, 160).replace(/\s+/g, " ").trim();
}

function scanText(text: string | undefined): string[] {
  if (!text) return [];
  const hits: string[] = [];
  if (HIDDEN_TAG.test(text)) hits.push("hidden-instruction-tag");
  if (FILE_PATH_EXFIL.test(text)) hits.push("file-path-exfiltration-target");
  if (CONCEAL.test(text)) hits.push("concealment-directive");
  if (IMPERATIVE.test(text)) hits.push("imperative-instruction");
  if (EXFIL_VERB.test(text) && EXTERNAL_ADDR.test(text))
    hits.push("exfiltration-to-external-destination");
  return hits;
}

/** Full-Schema Poisoning: scan every field of every tool, plus prompts,
 *  resources, and server instructions. */
export function scanToolPoisoning(discovery: McpDiscoveryLike): PoisonFinding[] {
  const findings: PoisonFinding[] = [];
  const add = (tool: string, field: string, text: string | undefined) => {
    for (const signal of scanText(text)) {
      findings.push({ tool, field, signal, snippet: snippet(text ?? "") });
    }
  };

  for (const tool of discovery.tools ?? []) {
    const name = tool.name ?? "(unnamed)";
    add(name, "description", tool.description);
    const schema = tool.inputSchema;
    if (schema && typeof schema === "object") {
      const s = schema as Record<string, unknown>;
      const props = (s.properties ?? {}) as Record<string, unknown>;
      for (const [pname, pval] of Object.entries(props)) {
        // Parameter NAME can itself encode instructions / file paths (FSP).
        // Scan both the raw name (so "id_rsa" matches) and a de-underscored
        // form (so "ignore_previous_instructions" reads as prose).
        add(name, `parameter name "${pname}"`, `${pname} ${pname.replace(/_/g, " ")}`);
        if (pval && typeof pval === "object") {
          const p = pval as Record<string, unknown>;
          add(name, `parameter "${pname}" description`, p.description as string);
          if (typeof p.default === "string")
            add(name, `parameter "${pname}" default`, p.default);
          // Non-standard keys inside a property are an injection vector.
          for (const key of Object.keys(p)) {
            if (!STANDARD_SCHEMA_KEYS.has(key)) {
              findings.push({
                tool: name,
                field: `parameter "${pname}" non-standard key "${key}"`,
                signal: "non-standard-schema-key",
                snippet: snippet(`${key}: ${JSON.stringify(p[key])}`),
              });
            }
          }
        }
      }
      // Required array can smuggle instruction-bearing field names.
      if (Array.isArray(s.required)) {
        add(name, "required array", s.required.join(" "));
      }
    }
  }
  for (const prompt of discovery.prompts ?? [])
    add(prompt.name ?? "(prompt)", "prompt description", prompt.description);
  for (const res of discovery.resources ?? [])
    add(res.uri ?? res.name ?? "(resource)", "resource description", res.description);
  if (discovery.instructions)
    add("(server)", "server instructions", discovery.instructions);

  return findings;
}

export interface ShadowFinding {
  tool: string;
  kind: "cross-tool-redirect" | "duplicate-name" | "shadows-other-tool";
  detail: string;
}

/** Namespace collision / cross-server shadowing / tool-name squatting. */
export function scanToolShadowing(discovery: McpDiscoveryLike): ShadowFinding[] {
  const findings: ShadowFinding[] = [];
  const tools = discovery.tools ?? [];
  const names = tools.map((t) => (t.name ?? "").trim()).filter(Boolean);

  // Duplicate / case-insensitive collisions.
  const seen = new Map<string, string>();
  for (const n of names) {
    const key = n.toLowerCase();
    const prev = seen.get(key);
    if (prev !== undefined) {
      findings.push({
        tool: n,
        kind: "duplicate-name",
        detail: `duplicate/near-duplicate tool name collides with "${prev}"`,
      });
    } else {
      seen.set(key, n);
    }
  }

  // A tool description that issues directives about a DIFFERENT tool, with a
  // redirection/exfiltration signal — the canonical shadowing PoC.
  for (const tool of tools) {
    const desc = tool.description ?? "";
    const self = (tool.name ?? "").toLowerCase();
    if (!desc) continue;
    const lower = desc.toLowerCase();
    const referenced = names.filter(
      (other) =>
        other.toLowerCase() !== self &&
        new RegExp(`\\b${escapeRegex(other)}\\b`, "i").test(desc),
    );
    const redirects =
      /\b(instead of|rather than|redirect|reroute|override|proxy|do not use|replace)\b/i.test(
        lower,
      ) ||
      (EXFIL_VERB.test(lower) && EXTERNAL_ADDR.test(desc)) ||
      CONCEAL.test(desc);
    if (referenced.length > 0 && redirects) {
      findings.push({
        tool: tool.name ?? "(unnamed)",
        kind: "cross-tool-redirect",
        detail: `description issues directives about other tool(s) [${referenced.join(", ")}] with a redirect/exfiltration signal`,
      });
    }
  }

  return findings;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Advanced Tool Poisoning Attack (ATPA): injection lives in a tool's RESULT,
 * not its metadata — e.g. a fabricated error demanding ~/.ssh/id_rsa to
 * "resolve" a failure, causing the model to issue a secondary exfil call.
 * Scans a tools/call result for instruction/exfil content in the OUTPUT.
 */
export function scanToolResultInjection(resultText: string): string[] {
  const hits: string[] = [];
  if (!resultText) return hits;
  const fabricatedError =
    /\b(error|failed|failure|unable|cannot (complete|proceed))\b/i.test(resultText) &&
    (FILE_PATH_EXFIL.test(resultText) ||
      /\b(provide|send|include|paste|share|read) (your |the )?(ssh|api[_ ]?key|token|credential|secret|private key|password)\b/i.test(
        resultText,
      ));
  if (fabricatedError)
    hits.push("tool result is a fabricated error demanding secrets/credentials (ATPA)");
  if (HIDDEN_TAG.test(resultText))
    hits.push("tool result contains hidden-instruction tags");
  if (IMPERATIVE.test(resultText) && (EXFIL_VERB.test(resultText) || FILE_PATH_EXFIL.test(resultText)))
    hits.push("tool result contains imperative instructions to read/exfiltrate");
  if (CONCEAL.test(resultText) && EXFIL_VERB.test(resultText))
    hits.push("tool result instructs a concealed exfiltration action");
  return hits;
}
