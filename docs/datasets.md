---
title: Datasets (NeMo Data Designer)
parent: Develop
nav_order: 5
---

# Synthetic Eval Datasets via NeMo Data Designer

Generate reproducible, versioned attack/eval datasets for **agents** and **MCP
servers** using [NVIDIA NeMo Data Designer](https://docs.nvidia.com/nemo/microservices/latest/design-synthetic-data-from-scratch-or-seeds/index.html),
then run them through the normal eval loop with **zero engine changes**.

Design rationale and the full contract live in
[`docs/specs/nemo-data-designer-datasets.md`](specs/nemo-data-designer-datasets.md).

## How it fits

Data Designer *generates* rows; wb-red-team *executes and grades* them. The only
integration point is a JSON file on disk that the existing `customAttacksFile`
path already understands:

```
NeMo Data Designer  ──rows──▶  data/datasets/<family>/<version>.json
                                        │  (customAttacksFile)
                                        ▼
   custom-attacks-loader ▶ attack-runner ▶ response-analyzer ▶ judge ▶ report
```

The generator is **out-of-band**: a Data Designer outage can never break a scan.

## One-time: bring up Data Designer

Run the Data Designer microservice (Docker Compose dev deployment per NVIDIA's
docs) and export credentials. The generator reuses the same NIM credentials as
the built-in `nim` provider — no new secrets:

```bash
export NVIDIA_API_KEY=nvapi-...
export NEMO_DATA_DESIGNER_URL=http://localhost:8080   # default
# optional, if your DD version differs:
# export NEMO_PREVIEW_PATH=/v1/data-designer/preview
# export NEMO_GENERATE_PATH=/v1/data-designer/jobs
```

## Generate a dataset

Presets live in `configs/datasets/` and are the tuning knobs (family, category
pool, counts, model, balance floor).

```bash
# Inspect a few records before committing to a full run
npm run gen:dataset -- --preset configs/datasets/nemo-mcp.preset.json --preview

# Full generate
npm run gen:dataset -- \
  --preset configs/datasets/nemo-mcp.preset.json \
  --out data/datasets/nemo-mcp/v1.json \
  --count 400
```

Flags: `--family <mcp|agent>`, `--preset <file>`, `--out <file>`,
`--count <n>`, `--seed <file>` (optional `{roles,surfaces}`), `--preview`.

The generator **fails closed**: it refuses to write if any row has a category
outside the `AttackCategory` union, an empty prompt/successCriteria, or a bad
severity. It prints a per-category histogram and warns on categories below the
preset's `perCategoryFloor`.

## Run the eval

Point a config at the dataset with `customAttacksOnly: true` for a pure,
reproducible regression eval (no planner, no runtime generation):

```bash
# configs/config-nemo-mcp-eval.example.json ships pointed at the fixture
npm start configs/config-nemo-mcp-eval.example.json
```

Swap `customAttacksFile` to your generated `v1.json` (or the directory, to load
every pack in it). Reports land in `report/` exactly as for any other run.

## Target-tailored generation (seed from source)

Generic datasets are useful, but the platform's edge is white-box knowledge. You
can seed generation from a real target's discovered tool graph, roles, and MCP
surface so the synthetic attacks reference *your* tools and chains.

```bash
# 1. Analyze the target (needs a config with codebasePath) and dump the analysis
npm run analyze:dump -- config.mytarget.json --out analysis.json

# 2. Generate, seeded from that analysis
npm run gen:dataset -- \
  --preset configs/datasets/nemo-mcp.preset.json \
  --from-analysis analysis.json \
  --out data/datasets/nemo-mcp/mytarget-v1.json --count 400
```

Precedence for role/surface seeds: `--seed` (explicit `{roles,surfaces}` JSON) >
`--from-analysis` (derived) > preset placeholders > built-in defaults. When
seeds are supplied they **replace** the preset's generic surfaces, so the
tailored values actually drive generation. `--seed` and `--from-analysis` are
unioned when both are given.

## In-run generation (tight coupling, optional)

For a one-pass "analyze → generate → execute" run, set `datasetGenerator` in the
config instead of generating a file first. The run analyzes the target, seeds a
Data Designer dataset from that live analysis, and merges the rows into the
run's attacks:

```jsonc
"attackConfig": {
  "customAttacksOnly": true,
  "datasetGenerator": "nemo",
  "datasetGeneratorConfig": {
    "preset": "configs/datasets/nemo-mcp.preset.json",
    "count": 60,
    "seedFromAnalysis": true
  }
}
```

See `configs/config-nemo-inrun.example.json`. This is **fail-soft**: if Data
Designer is unreachable or produces no valid rows, the run logs a non-fatal
notice and continues with any file-based custom attacks. For reproducible,
diffable datasets prefer the offline `npm run gen:dataset` flow — the in-run
hook is a convenience, not the recommended default.

## Dashboard UI

The dashboard exposes datasets as a first-class surface:

- **Datasets tab** — lists every dataset under `data/datasets/**` with row count,
  family, and top categories, and has a "Generate" form (family + row count +
  version name) that calls the generator. Generation requires the Data Designer
  service to be reachable.
- **Launch Scan → Evaluation Dataset** — pick a generated dataset as the scan's
  attack set (`customAttacksFile`), and optionally toggle **Dataset-only
  (regression eval)** (`customAttacksOnly`) for a reproducible run.

An evaluation is just a scan whose attack set is a dataset — results appear in
the existing Reports / Risk / Compliance views, so score-over-time tracking uses
the same reporting you already have.

Server endpoints: `GET /api/datasets`, `POST /api/datasets/generate`.

## Row schema

Rows use the exact shape the loader already accepts:

```jsonc
{
  "category": "tool_chain_hijack",   // must be an AttackCategory (155 values)
  "name": "…",
  "prompt": "…attacker message…",     // [Turn N] markers supported for multi-turn
  "role": "user",
  "severity": "critical",             // critical|high|medium|low
  "successCriteria": "…observable success condition for the judge…",
  "description": "Synthetic (nemo). family=mcp strategy=…",
  "note": "generator=nemo-data-designer version=1"
}
```

## Families

| Family | Categories | Use |
|---|---|---|
| `mcp` | tool-chain / cross-tenant / injection / debug-access / … | MCP servers with a tool/prompt/resource surface |
| `agent` | prompt-injection / goal-hijack / memory-poisoning / PII / … | conversational & agentic apps |

Both share one schema and one eval loop; only the seed pools differ.

## Testing

`tests/dataset-nemo.test.ts` covers the category-union guard, fail-closed
validation, config-builder ordering, record mapping, and a fixture that
round-trips through the real `custom-attacks-loader`. The generator smoke test
against a live Data Designer is network-gated and not part of CI.
