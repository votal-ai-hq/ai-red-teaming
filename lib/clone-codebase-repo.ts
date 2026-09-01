import { execFileSync } from "node:child_process";
import type { Config } from "./types.js";

const HTTPS_REPO = /^https?:\/\/[^\s]+$/i;
const GIT_SSH = /^git@[^\s:]+:[^\s]+$/;
const BRANCH_RE = /^[A-Za-z0-9._/\-]+$/;

export type CloneConfig = Pick<
  Config,
  "codebaseRepo" | "codebasePath" | "codebaseRepoBranch" | "codebaseRepoToken"
>;

/**
 * Build a git-clone URL. Rejects shell metacharacters and option-injection
 * (`-e`, `file://`). Token is applied via URL username, never string concat
 * into a shell command.
 */
export function resolveCloneUrl(repoUrl: string, token?: string): string {
  const trimmed = repoUrl.trim();
  if (!trimmed || /\s/.test(trimmed) || trimmed.startsWith("-")) {
    throw new Error("Invalid codebaseRepo URL");
  }

  if (GIT_SSH.test(trimmed)) {
    if (token?.trim()) {
      throw new Error("codebaseRepoToken cannot be used with SSH git URLs");
    }
    return trimmed;
  }

  if (!HTTPS_REPO.test(trimmed)) {
    throw new Error("codebaseRepo must be an http(s) URL or git@host:path");
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error("Invalid codebaseRepo URL");
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("codebaseRepo must use http(s)");
  }
  if (parsed.username || parsed.password) {
    throw new Error(
      "codebaseRepo must not embed credentials; use codebaseRepoToken",
    );
  }

  const tok = token?.trim() || "";
  if (tok) {
    if (/\s/.test(tok) || tok.includes("@") || tok.startsWith("-")) {
      throw new Error("Invalid codebaseRepoToken");
    }
    parsed.username = tok;
    parsed.password = "";
  }

  return parsed.toString();
}

export function resolveCloneBranch(branch: string | undefined): string | null {
  const value = (branch || "").trim();
  if (!value) return null;
  if (
    !BRANCH_RE.test(value) ||
    value.startsWith("-") ||
    value.includes("..")
  ) {
    throw new Error("Invalid codebaseRepoBranch");
  }
  return value;
}

/**
 * Clone `config.codebaseRepo` into `destDir` using git argv (no shell).
 * Returns false when there is nothing to clone.
 */
export function cloneCodebaseRepoToDir(
  config: CloneConfig,
  destDir: string,
): boolean {
  if (!config.codebaseRepo || config.codebasePath) return false;

  const branch = resolveCloneBranch(config.codebaseRepoBranch);
  const token =
    config.codebaseRepoToken || process.env.CODEBASE_REPO_TOKEN || "";
  const repoUrl = resolveCloneUrl(config.codebaseRepo, token);

  const args = ["clone", "--depth", "1"];
  if (branch) args.push("--branch", branch);
  args.push("--", repoUrl, destDir);

  execFileSync("git", args, {
    timeout: 120_000,
    stdio: "pipe",
    windowsHide: process.platform === "win32",
  });
  return true;
}
