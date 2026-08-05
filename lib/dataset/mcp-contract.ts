import Ajv, { type ValidateFunction } from "ajv";
import Ajv2019 from "ajv/dist/2019.js";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import type { AttackCategory } from "../types.js";
import {
  isMcpTaskMetricCompatible,
  mcpQualityTaskIssue,
} from "./quality-set.js";
import type {
  DatasetRow,
  DatasetPreset,
  DatasetSeeds,
  McpDatasetContract,
  McpDatasetToolContract,
  QualityRow,
} from "./types.js";

const DIRECT_CATEGORY_REQUIREMENTS: Partial<Record<AttackCategory, string>> = {
  agentic_workflow_bypass: "an agent workflow with observable intermediate steps",
  cross_session_injection: "at least two isolated MCP sessions",
  cross_tenant_access: "at least two authenticated tenant identities",
  indirect_prompt_injection: "a downstream agent that consumes returned content",
  plugin_manifest_spoofing: "manifest or installation lifecycle inspection",
  rbac_bypass: "at least two authenticated permission levels",
  sdk_dependency_attack: "dependency or package lifecycle inspection",
  session_hijacking: "session credential mutation",
  tool_chain_hijack: "multiple ordered MCP operations",
  tool_output_manipulation: "a downstream agent that consumes a tool result",
};

const INJECTION_CATEGORIES = new Set<AttackCategory>([
  "prompt_template_injection",
  "shell_injection",
  "sql_injection",
  "unexpected_code_exec",
]);

const TOOL_SURFACE_RE = /^tool\s+"([^"]+)"/i;
const PROMPT_SURFACE_RE = /^MCP\s+prompt\s+"([^"]+)"/i;
const RESOURCE_SURFACE_RE = /^MCP\s+resource\s+"([^"]+)"/i;
const schemaValidators = new WeakMap<object, ValidateFunction>();

const draft7 = addFormats(
  new Ajv({ allErrors: true, strict: false, allowUnionTypes: true }),
);
const draft2019 = addFormats(
  new Ajv2019({ allErrors: true, strict: false, allowUnionTypes: true }),
);
const draft2020 = addFormats(
  new Ajv2020({ allErrors: true, strict: false, allowUnionTypes: true }),
);

function clean(value: string): string {
  return value.trim().replace(/\s+/g, " ");
}

function unique(values: Iterable<string>): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = clean(value);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    result.push(normalized);
  }
  return result;
}

function hasSurface(contract: McpDatasetContract): boolean {
  return (
    contract.tools.length > 0 ||
    contract.prompts.length > 0 ||
    contract.resources.length > 0
  );
}

/** Normalize an object or JSON string into a tool schema without guessing. */
export function mcpToolContract(
  name: string,
  schemaValue: unknown,
): McpDatasetToolContract {
  const tool: McpDatasetToolContract = { name: clean(name) };
  if (schemaValue === undefined || schemaValue === null || schemaValue === "") {
    return tool;
  }
  if (typeof schemaValue === "object" && !Array.isArray(schemaValue)) {
    tool.inputSchema = schemaValue as Record<string, unknown>;
    return tool;
  }
  if (typeof schemaValue !== "string") {
    tool.schemaError = `expected an object or JSON text, received ${typeof schemaValue}`;
    return tool;
  }
  try {
    const parsed = JSON.parse(schemaValue) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      tool.schemaError = "schema JSON must be an object";
    } else {
      tool.inputSchema = parsed as Record<string, unknown>;
    }
  } catch (error) {
    tool.schemaError = `schema is not valid JSON: ${(error as Error).message}`;
  }
  return tool;
}

/** Recover a machine-readable contract from legacy surface strings. */
export function mcpContractFromSurfaces(
  surfaces: Iterable<string>,
  roles: Iterable<string> = [],
): McpDatasetContract | undefined {
  const tools: McpDatasetToolContract[] = [];
  const prompts: string[] = [];
  const resources: string[] = [];
  const seenTools = new Set<string>();

  for (const raw of surfaces) {
    const surface = String(raw ?? "").trim();
    const toolMatch = TOOL_SURFACE_RE.exec(surface);
    if (toolMatch) {
      const name = clean(toolMatch[1]);
      if (seenTools.has(name)) continue;
      seenTools.add(name);
      const marker = surface.lastIndexOf(" schema=");
      tools.push(
        mcpToolContract(
          name,
          marker >= 0 ? surface.slice(marker + " schema=".length) : undefined,
        ),
      );
      continue;
    }
    const promptMatch = PROMPT_SURFACE_RE.exec(surface);
    if (promptMatch) {
      prompts.push(promptMatch[1]);
      continue;
    }
    const resourceMatch = RESOURCE_SURFACE_RE.exec(surface);
    if (resourceMatch) resources.push(resourceMatch[1]);
  }

  const contract: McpDatasetContract = {
    tools,
    prompts: unique(prompts),
    resources: unique(resources),
    roles: unique(roles),
  };
  return hasSurface(contract) ? contract : undefined;
}

/** Prefer the structured seed contract, with legacy surface parsing as fallback. */
export function resolveMcpDatasetContract(
  seeds: DatasetSeeds | undefined,
): McpDatasetContract | undefined {
  if (!seeds) return undefined;
  if (seeds.mcpContract && hasSurface(seeds.mcpContract)) {
    return seeds.mcpContract;
  }
  return mcpContractFromSurfaces(seeds.surfaces ?? [], seeds.roles ?? []);
}

/** Resolve the effective contract using the same seed-over-preset precedence. */
export function resolveMcpGenerationContract(
  preset: DatasetPreset,
  seeds: DatasetSeeds | undefined,
): McpDatasetContract | undefined {
  const legacy = mcpContractFromSurfaces(
    seeds?.surfaces ?? preset.surfaces ?? [],
    seeds?.roles ?? preset.roles ?? [],
  );
  return mergeMcpContracts(seeds?.mcpContract, legacy);
}

/** Merge contracts without losing the primary schema for a duplicate tool. */
export function mergeMcpContracts(
  primary: McpDatasetContract | undefined,
  secondary: McpDatasetContract | undefined,
): McpDatasetContract | undefined {
  if (!primary) return secondary;
  if (!secondary) return primary;

  const tools = new Map<string, McpDatasetToolContract>();
  for (const tool of [...primary.tools, ...secondary.tools]) {
    const existing = tools.get(tool.name);
    if (!existing) {
      tools.set(tool.name, tool);
    } else if (!existing.inputSchema && tool.inputSchema) {
      tools.set(tool.name, { ...existing, inputSchema: tool.inputSchema });
    }
  }
  return {
    tools: [...tools.values()],
    prompts: unique([...primary.prompts, ...secondary.prompts]),
    resources: unique([...primary.resources, ...secondary.resources]),
    roles: unique([...primary.roles, ...secondary.roles]),
  };
}

/**
 * The generated MCP security runner executes one direct protocol operation.
 * Exclude categories whose success condition needs state or an agent loop.
 */
export function resolveDirectMcpCategories(
  categories: AttackCategory[],
  explicit: boolean,
): AttackCategory[] {
  const unsupported = categories.filter((category) =>
    Boolean(DIRECT_CATEGORY_REQUIREMENTS[category]),
  );
  if (explicit && unsupported.length > 0) {
    const detail = unsupported
      .map((category) => `${category} (${DIRECT_CATEGORY_REQUIREMENTS[category]})`)
      .join(", ");
    throw new Error(`MCP direct-call generation cannot measure: ${detail}`);
  }
  return categories.filter((category) => !DIRECT_CATEGORY_REQUIREMENTS[category]);
}

function schemaCompiler(schema: Record<string, unknown>): ValidateFunction {
  const cached = schemaValidators.get(schema);
  if (cached) return cached;
  const dialect = String(schema.$schema ?? "").toLowerCase();
  const ajv = dialect.includes("2020-12")
    ? draft2020
    : dialect.includes("2019-09")
      ? draft2019
      : draft7;
  const validator = ajv.compile(schema);
  schemaValidators.set(schema, validator);
  return validator;
}

function schemaErrors(validate: ValidateFunction): string {
  return (validate.errors ?? [])
    .slice(0, 4)
    .map((error) => `${error.instancePath || "/"} ${error.message ?? "is invalid"}`)
    .join("; ");
}

function decodeJsonPointer(root: unknown, pointer: string): unknown {
  if (!pointer.startsWith("#/")) return undefined;
  return pointer
    .slice(2)
    .split("/")
    .map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"))
    .reduce<unknown>((current, part) => {
      if (!current || typeof current !== "object") return undefined;
      return (current as Record<string, unknown>)[part];
    }, root);
}

/** Whether a schema exposes a value capable of carrying an injection payload. */
export function hasOpenStringInput(schema: Record<string, unknown>): boolean {
  const visited = new Set<object>();
  const walk = (value: unknown): boolean => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    if (visited.has(value)) return false;
    visited.add(value);
    const node = value as Record<string, unknown>;
    if (typeof node.$ref === "string") {
      return walk(decodeJsonPointer(schema, node.$ref));
    }
    const type = node.type;
    const permitsString =
      type === "string" ||
      (Array.isArray(type) && type.includes("string")) ||
      (type === undefined && Object.keys(node).length === 0);
    if (permitsString && node.const === undefined && !Array.isArray(node.enum)) {
      return true;
    }
    if (node.additionalProperties === true) return true;
    for (const key of ["properties", "patternProperties", "$defs", "definitions"]) {
      const children = node[key];
      if (children && typeof children === "object" && !Array.isArray(children)) {
        if (Object.values(children).some(walk)) return true;
      }
    }
    if (walk(node.items)) return true;
    for (const key of ["allOf", "anyOf", "oneOf", "prefixItems"]) {
      if (Array.isArray(node[key]) && (node[key] as unknown[]).some(walk)) return true;
    }
    return false;
  };
  return walk(schema);
}

function resourceMatches(declared: string, requested: string): boolean {
  if (declared === requested) return true;
  if (!declared.includes("{")) return false;
  const escaped = declared
    .split(/(\{[^}]+\})/g)
    .map((part) =>
      /^\{[^}]+\}$/.test(part)
        ? "[^/]+"
        : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
    )
    .join("");
  return new RegExp(`^${escaped}$`).test(requested);
}

/** Contract-level errors for a structurally valid MCP security row. */
export function validateMcpSecurityContract(
  row: DatasetRow,
  contract: McpDatasetContract,
): string[] {
  const errors: string[] = [];
  const requiredHarness = DIRECT_CATEGORY_REQUIREMENTS[row.category as AttackCategory];
  if (requiredHarness) {
    errors.push(`category requires ${requiredHarness}; one direct operation is insufficient`);
  }
  if (row.role && contract.roles.length > 0 && !contract.roles.includes(row.role)) {
    errors.push(`role "${row.role}" is not declared by the target contract`);
  }
  if (
    INJECTION_CATEGORIES.has(row.category as AttackCategory) &&
    row._mcpOperation !== "tools/call"
  ) {
    errors.push(`category "${row.category}" requires a tool call with a schema-visible string input`);
  }

  if (row._mcpOperation === "tools/call") {
    const tool = contract.tools.find((candidate) => candidate.name === row._mcpTool);
    if (!tool) {
      errors.push(`tool "${row._mcpTool}" is not declared by the target contract`);
      return errors;
    }
    if (tool.schemaError) {
      errors.push(`tool "${tool.name}" has an unusable input schema: ${tool.schemaError}`);
      return errors;
    }
    if (!tool.inputSchema) {
      errors.push(`tool "${tool.name}" has no input schema to validate arguments`);
      return errors;
    }
    try {
      const validate = schemaCompiler(tool.inputSchema);
      if (!validate(row._mcpArguments ?? {})) {
        errors.push(`arguments for tool "${tool.name}" violate its schema: ${schemaErrors(validate)}`);
      }
    } catch (error) {
      errors.push(`tool "${tool.name}" has an invalid input schema: ${(error as Error).message}`);
    }
    if (
      INJECTION_CATEGORIES.has(row.category as AttackCategory) &&
      !hasOpenStringInput(tool.inputSchema)
    ) {
      errors.push(`category "${row.category}" needs an unconstrained string input`);
    }
  } else if (row._mcpOperation === "prompts/get") {
    if (!contract.prompts.includes(row._mcpPrompt ?? "")) {
      errors.push(`prompt "${row._mcpPrompt}" is not declared by the target contract`);
    }
  } else if (row._mcpOperation === "resources/read") {
    const uri = row._mcpResourceUri ?? "";
    if (!contract.resources.some((declared) => resourceMatches(declared, uri))) {
      errors.push(`resource "${uri}" is not declared by the target contract`);
    }
  }
  return errors;
}

/** Contract/scorer errors for a structurally valid MCP quality row. */
export function validateMcpQualityContract(
  row: QualityRow,
  contract: McpDatasetContract,
): string[] {
  const errors: string[] = [];
  const toolNames = new Set(contract.tools.map((tool) => tool.name));
  const unknownTools = (row.expectedTools ?? []).filter((tool) => !toolNames.has(tool));
  if (unknownTools.length > 0) {
    errors.push(`expectedTools contains tools not declared by the target: ${unique(unknownTools).join(", ")}`);
  }

  const unsupportedReason = mcpQualityTaskIssue(row.task);
  if (unsupportedReason) {
    errors.push(`task "${row.task}" cannot be scored: ${unsupportedReason}`);
    return errors;
  }
  if (!isMcpTaskMetricCompatible(row.task, row.metric)) {
    errors.push(`metric "${row.metric}" does not measure MCP task "${row.task}"`);
  }
  return errors;
}
