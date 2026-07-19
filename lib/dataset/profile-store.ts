/**
 * Persist reusable AppProfiles as JSON under configs/profiles/. A profile is
 * built once per target app and reused across security + quality datasets and
 * re-runs (the reproducible-eval goal).
 *
 * Filenames are derived from the (already validated, filename-safe) profile
 * name. All reads/writes are contained to configs/profiles/ so a crafted name
 * can't escape the directory.
 */
import {
  readFileSync,
  writeFileSync,
  existsSync,
  readdirSync,
  mkdirSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { validateProfile, type AppProfile } from "./app-profile.js";

const PROFILES_SUBDIR = join("configs", "profiles");

function profilesDir(root: string): string {
  return join(root, PROFILES_SUBDIR);
}

/** Resolve the on-disk path for a profile name, asserting containment. */
function profilePath(root: string, name: string): string {
  const dir = profilesDir(root);
  const abs = resolve(dir, `${name}.json`);
  // Defence in depth: validateProfile already restricts name, but never trust it.
  if (abs !== join(dir, `${name}.json`) || !abs.startsWith(resolve(dir))) {
    throw new Error(`invalid profile name "${name}"`);
  }
  return abs;
}

export interface ProfileSummary {
  name: string;
  description?: string;
  source?: string;
  toolCount: number;
  ruleCount: number;
  roleCount: number;
}

function summarize(p: AppProfile): ProfileSummary {
  return {
    name: p.name,
    description: p.description,
    source: p.source,
    toolCount: p.tools?.length ?? 0,
    ruleCount: p.businessRules?.length ?? 0,
    roleCount: p.roles?.length ?? 0,
  };
}

/** List saved profiles (summaries), newest filename first. Missing dir -> []. */
export function listProfiles(root: string): ProfileSummary[] {
  const dir = profilesDir(root);
  if (!existsSync(dir)) return [];
  const out: ProfileSummary[] = [];
  for (const file of readdirSync(dir)) {
    if (!file.endsWith(".json")) continue;
    try {
      const p = validateProfile(
        JSON.parse(readFileSync(join(dir, file), "utf-8")),
      );
      out.push(summarize(p));
    } catch {
      // Skip unreadable / invalid profile files rather than failing the list.
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

/** Load one profile by name. Throws if missing or invalid. */
export function loadProfile(root: string, name: string): AppProfile {
  const clean = validateProfile({ name }).name; // reuse name validation
  const abs = profilePath(root, clean);
  if (!existsSync(abs)) {
    throw new Error(`profile not found: ${name}`);
  }
  return validateProfile(JSON.parse(readFileSync(abs, "utf-8")));
}

/** Validate + write a profile. Returns the repo-relative path written. */
export function saveProfile(root: string, raw: unknown): string {
  const profile = validateProfile(raw);
  const dir = profilesDir(root);
  mkdirSync(dir, { recursive: true });
  const abs = profilePath(root, profile.name);
  writeFileSync(abs, JSON.stringify(profile, null, 2) + "\n", "utf-8");
  return join(PROFILES_SUBDIR, `${profile.name}.json`);
}
