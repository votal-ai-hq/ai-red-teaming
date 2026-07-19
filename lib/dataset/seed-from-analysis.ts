/**
 * Derive dataset generation seeds from a white-box CodebaseAnalysis.
 *
 * This is what makes the generated dataset *target-tailored* rather than
 * generic: the MCP tool graph, roles, and MCP surface discovered by
 * `lib/codebase-analyzer.ts` become the sampler seed values Data Designer
 * conditions its LLM columns on.
 *
 * Pure + I/O-free so it can be unit-tested against a fixture analysis.
 *
 * See docs/specs/nemo-data-designer-datasets.md §8 (Phase 2).
 */
import type { CodebaseAnalysis } from "../types.js";
import type { DatasetSeeds } from "./types.js";

const MAX_SURFACES = 24;
const MAX_ROLES = 12;

function clean(s: string): string {
  return s.trim().replace(/\s+/g, " ");
}

function dedupeCap(values: string[], cap: number): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const v of values) {
    const c = clean(v);
    if (!c) continue;
    const key = c.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
    if (out.length >= cap) break;
  }
  return out;
}

/**
 * Build seeds from an analysis. Surfaces are drawn from (in priority order):
 * discovered tools, tool-chain source→sink pairs, MCP prompts, MCP resources.
 * Roles come from discovered RBAC roles. Empty analysis yields empty seeds, so
 * the config-builder falls back to its generic defaults.
 */
export function seedsFromAnalysis(analysis: CodebaseAnalysis): DatasetSeeds {
  const surfaceCandidates: string[] = [];

  for (const t of analysis.tools ?? []) {
    if (!t?.name) continue;
    const desc = t.description ? ` — ${clean(t.description).slice(0, 60)}` : "";
    surfaceCandidates.push(`tool "${clean(t.name)}"${desc}`);
  }

  for (const chain of analysis.toolChains ?? []) {
    if (chain?.source && chain?.sink) {
      surfaceCandidates.push(
        `tool chain ${clean(chain.source)} → ${clean(chain.sink)} (${chain.risk})`,
      );
    }
  }

  for (const p of analysis.mcpSurface?.prompts ?? []) {
    surfaceCandidates.push(`MCP prompt "${clean(p)}"`);
  }
  for (const r of analysis.mcpSurface?.resources ?? []) {
    surfaceCandidates.push(`MCP resource "${clean(r)}"`);
  }

  const roles = dedupeCap(
    (analysis.roles ?? []).map((r) => r?.name).filter(Boolean) as string[],
    MAX_ROLES,
  );
  const surfaces = dedupeCap(surfaceCandidates, MAX_SURFACES);

  const seeds: DatasetSeeds = {};
  if (roles.length) seeds.roles = roles;
  if (surfaces.length) seeds.surfaces = surfaces;
  return seeds;
}

/** Merge two seed sets (union, deduped). `primary` values come first. */
export function mergeSeeds(
  primary: DatasetSeeds | undefined,
  secondary: DatasetSeeds | undefined,
): DatasetSeeds | undefined {
  if (!primary) return secondary;
  if (!secondary) return primary;
  const merged: DatasetSeeds = {};
  const roles = dedupeCap(
    [...(primary.roles ?? []), ...(secondary.roles ?? [])],
    MAX_ROLES,
  );
  const surfaces = dedupeCap(
    [...(primary.surfaces ?? []), ...(secondary.surfaces ?? [])],
    MAX_SURFACES,
  );
  if (roles.length) merged.roles = roles;
  if (surfaces.length) merged.surfaces = surfaces;
  return merged;
}
