import { describe, it, expect, afterEach } from "vitest";
import { rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { summarizeRows } from "../lib/dataset/list.js";
import {
  saveDatasetStore,
  readDatasetRowsStore,
  listDatasetsStore,
  datasetExistsStore,
  deleteDatasetStore,
  renameDatasetStore,
  datasetDbEnabled,
} from "../lib/dataset/dataset-store.js";

describe("summarizeRows", () => {
  it("infers security kind + category histogram", () => {
    const s = summarizeRows("data/datasets/nemo-mcp/v1.json", [
      { category: "tool_misuse", prompt: "x" },
      { category: "tool_misuse", prompt: "y" },
      { category: "rbac_bypass", prompt: "z" },
    ]);
    expect(s.kind).toBe("security");
    expect(s.family).toBe("mcp");
    expect(s.name).toBe("v1");
    expect(s.rowCount).toBe(3);
    expect(s.histogram).toEqual({ tool_misuse: 2, rbac_bypass: 1 });
    expect(s.sizeBytes).toBeGreaterThan(0);
  });

  it("infers quality kind + task histogram", () => {
    const s = summarizeRows("data/datasets/quality-agent/v1.json", [
      { task: "tool_selection", input: "a" },
      { task: "rag_answer", input: "b" },
    ]);
    expect(s.kind).toBe("quality");
    expect(s.family).toBe("agent");
    expect(s.histogram).toEqual({ tool_selection: 1, rag_answer: 1 });
  });
});

// File-mode store (no DATABASE_URL). Skipped automatically if a DB is set so we
// never touch a real database from unit tests. Writes under a temp dataset dir
// and cleans it up.
describe.skipIf(datasetDbEnabled())("dataset-store (file mode)", () => {
  const TENANT = "unused-in-file-mode";
  const PATH = "data/datasets/__store_test__/roundtrip.json";
  const repoRoot = join(import.meta.dirname, "..");

  afterEach(() => {
    const dir = join(repoRoot, "data", "datasets", "__store_test__");
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  });

  it("save → exists → read → list → delete round-trips on disk", async () => {
    const rows = [
      { category: "tool_misuse", name: "c1", prompt: "p1", severity: "high", successCriteria: "sc" },
      { category: "rbac_bypass", name: "c2", prompt: "p2", severity: "low", successCriteria: "sc" },
    ];
    const summary = await saveDatasetStore(TENANT, PATH, rows);
    expect(summary.rowCount).toBe(2);

    expect(await datasetExistsStore(TENANT, PATH)).toBe(true);
    const back = await readDatasetRowsStore(TENANT, PATH);
    expect(back).toHaveLength(2);
    expect((back![0] as { prompt: string }).prompt).toBe("p1");

    const all = await listDatasetsStore(TENANT);
    expect(all.some((d) => d.path === PATH && d.rowCount === 2)).toBe(true);

    await deleteDatasetStore(TENANT, PATH);
    expect(await datasetExistsStore(TENANT, PATH)).toBe(false);
    expect(await readDatasetRowsStore(TENANT, PATH)).toBeNull();
  });

  it("rename moves the dataset, keeps its rows, and frees the old path", async () => {
    const rows = [
      { category: "tool_misuse", name: "c1", prompt: "p1", severity: "high", successCriteria: "sc" },
    ];
    await saveDatasetStore(TENANT, PATH, rows);
    const RENAMED = "data/datasets/__store_test__/v2-renamed.json";

    const summary = await renameDatasetStore(TENANT, PATH, RENAMED);
    expect(summary?.path).toBe(RENAMED);
    expect(summary?.name).toBe("v2-renamed");
    expect(summary?.rowCount).toBe(1);
    // family/kind are derived from the directory, so they survive the rename.
    expect(summary?.kind).toBe("security");

    expect(await datasetExistsStore(TENANT, RENAMED)).toBe(true);
    expect(await datasetExistsStore(TENANT, PATH)).toBe(false);
    const back = await readDatasetRowsStore(TENANT, RENAMED);
    expect((back![0] as { prompt: string }).prompt).toBe("p1");
  });

  it("renaming a dataset that doesn't exist returns null", async () => {
    const missing = await renameDatasetStore(
      TENANT,
      "data/datasets/__store_test__/nope.json",
      "data/datasets/__store_test__/other.json",
    );
    expect(missing).toBeNull();
  });
});
