import { afterEach, describe, expect, it, vi } from "vitest";

const execFileSync = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", () => ({
  execFileSync,
}));

import {
  cloneCodebaseRepoToDir,
  resolveCloneBranch,
  resolveCloneUrl,
} from "../lib/clone-codebase-repo.js";

const ORIGINAL_TOKEN = process.env.CODEBASE_REPO_TOKEN;

afterEach(() => {
  execFileSync.mockReset();
  if (ORIGINAL_TOKEN === undefined) {
    delete process.env.CODEBASE_REPO_TOKEN;
  } else {
    process.env.CODEBASE_REPO_TOKEN = ORIGINAL_TOKEN;
  }
});

describe("resolveCloneUrl", () => {
  it("accepts https URLs", () => {
    expect(resolveCloneUrl("https://github.com/acme/app.git")).toBe(
      "https://github.com/acme/app.git",
    );
  });

  it("injects token as URL username", () => {
    expect(
      resolveCloneUrl("https://github.com/acme/app.git", "ghp_abc"),
    ).toBe("https://ghp_abc@github.com/acme/app.git");
  });

  it("accepts SSH scp-style URLs without a token", () => {
    expect(resolveCloneUrl("git@github.com:acme/app.git")).toBe(
      "git@github.com:acme/app.git",
    );
  });

  it("rejects shell metacharacters in the URL", () => {
    expect(() =>
      resolveCloneUrl("https://github.com/acme/app.git; id"),
    ).toThrow(/Invalid codebaseRepo URL|must be an http/);
  });

  it("rejects option-injection URLs", () => {
    expect(() => resolveCloneUrl("-u./evil")).toThrow(/Invalid codebaseRepo URL/);
  });

  it("rejects file:// URLs", () => {
    expect(() => resolveCloneUrl("file:///etc/passwd")).toThrow(/http\(s\)/);
  });

  it("rejects embedded credentials", () => {
    expect(() =>
      resolveCloneUrl("https://user:pass@github.com/acme/app.git"),
    ).toThrow(/must not embed credentials/);
  });

  it("rejects SSH URLs when a token is set", () => {
    expect(() =>
      resolveCloneUrl("git@github.com:acme/app.git", "tok"),
    ).toThrow(/SSH/);
  });
});

describe("resolveCloneBranch", () => {
  it("returns null for empty branch", () => {
    expect(resolveCloneBranch(undefined)).toBeNull();
    expect(resolveCloneBranch("")).toBeNull();
  });

  it("accepts normal branch names", () => {
    expect(resolveCloneBranch("main")).toBe("main");
    expect(resolveCloneBranch("feat/foo-1")).toBe("feat/foo-1");
  });

  it("rejects command separators", () => {
    expect(() => resolveCloneBranch("main; calc")).toThrow(
      /Invalid codebaseRepoBranch/,
    );
  });

  it("rejects option-looking branches", () => {
    expect(() => resolveCloneBranch("-b")).toThrow(/Invalid codebaseRepoBranch/);
  });
});

describe("cloneCodebaseRepoToDir", () => {
  it("no-ops when codebasePath is already set", () => {
    expect(
      cloneCodebaseRepoToDir(
        {
          codebaseRepo: "https://github.com/acme/app.git",
          codebasePath: "/tmp/src",
        },
        "/tmp/dest",
      ),
    ).toBe(false);
    expect(execFileSync).not.toHaveBeenCalled();
  });

  it("invokes git with argv, not a shell string", () => {
    execFileSync.mockReturnValue(Buffer.from(""));
    expect(
      cloneCodebaseRepoToDir(
        {
          codebaseRepo: "https://github.com/acme/app.git",
          codebaseRepoBranch: "release",
        },
        "/tmp/dest",
      ),
    ).toBe(true);
    expect(execFileSync).toHaveBeenCalledTimes(1);
    const [cmd, args, opts] = execFileSync.mock.calls[0];
    expect(cmd).toBe("git");
    expect(args).toEqual([
      "clone",
      "--depth",
      "1",
      "--branch",
      "release",
      "--",
      "https://github.com/acme/app.git",
      "/tmp/dest",
    ]);
    expect(opts).toMatchObject({ timeout: 120_000, stdio: "pipe" });
  });
});
