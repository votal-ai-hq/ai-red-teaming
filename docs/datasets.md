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
docs) and export credentials. Data Designer is **not NVIDIA-locked** — it can
back generation with NIM *or* OpenAI (and other providers). Set the API key for
whichever provider your preset uses; the client picks the first of
`NEMO_API_KEY`, `NVIDIA_API_KEY`, `OPENAI_API_KEY`:

```bash
# NIM-backed (default presets, provider: "nim")
export NVIDIA_API_KEY=nvapi-...
# — or — OpenAI-backed (provider: "openai", e.g. nemo-mcp-openai.preset.json)
export OPENAI_API_KEY=sk-...

export NEMO_DATA_DESIGNER_URL=http://localhost:8080   # default
# optional, if your DD version differs:
# export NEMO_PREVIEW_PATH=/v1/data-designer/preview
# export NEMO_GENERATE_PATH=/v1/data-designer/jobs
```

The generation provider + model live in the preset (`provider`,
`generationModel`). `configs/datasets/nemo-mcp-openai.preset.json` is a ready
OpenAI-backed variant.

## Generate a dataset

Presets live in `configs/datasets/` and are the tuning knobs (family, category
pool, counts, model, balance floor).

```bash
# First capture the MCP target's real tools, schemas, prompts, and resources.
npm run analyze:dump -- config.mytarget.json --out analysis.json

# Inspect a few executable records before committing to a full run.
npm run gen:dataset -- \
  --preset configs/datasets/nemo-mcp.preset.json \
  --from-analysis analysis.json \
  --preview

# Full generate
npm run gen:dataset -- \
  --preset configs/datasets/nemo-mcp.preset.json \
  --from-analysis analysis.json \
  --out data/datasets/nemo-mcp/v1.json \
  --count 400
```

Flags: `--family <mcp|agent>`, `--preset <file>`, `--out <file>`,
`--count <n>`, `--seed <file>` (optional `{roles,surfaces}`), `--preview`.

MCP security generation requires a target analysis, imported MCP profile, or
explicit seed containing concrete `tool "name"`, `MCP prompt "name"`, or
`MCP resource "uri"` surfaces. Generic MCP surfaces cannot produce calls that
the target exposes, so generation fails before spending model tokens when no
executable surface is available. Direct MCP datasets are single-operation
datasets; use the agent family for multi-turn conversation evals.

Each generated MCP row includes the protocol fields consumed by the target
adapter:

```json
{
  "prompt": "{\"bookingId\":\"BK-7001\",\"newAmountINR\":1}",
  "_mcpOperation": "tools/call",
  "_mcpTool": "override_price",
  "_mcpArguments": {
    "bookingId": "BK-7001",
    "newAmountINR": 1
  }
}
```

The generator **fails closed**: it refuses to write if any row has a category
outside the `AttackCategory` union, an empty prompt/successCriteria, a bad
severity, or (for MCP) missing operation-specific execution fields. It prints a
per-category histogram and warns on categories below the preset's
`perCategoryFloor`.

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

Agent datasets can be generic. MCP security datasets must be seeded from a real
target's discovered tool graph, roles, and MCP surface so every generated row
references an operation the server actually exposes.

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
  version name) that calls the generator. The optional **Seed from target
  analysis** field takes a scan config path (under `configs/`, with a
  `codebasePath`); the target is analyzed and generation is seeded from its
  discovered tools/roles/MCP surface for target-tailored attacks. Generation
  requires the Data Designer service to be reachable.
- **Launch Scan → Evaluation Dataset** — pick a generated dataset as the scan's
  attack set (`customAttacksFile`), and optionally toggle **Dataset-only
  (regression eval)** (`customAttacksOnly`) for a reproducible run.

An evaluation is just a scan whose attack set is a dataset — results appear in
the existing Reports / Risk / Compliance views.

**Score over time (regression tracking).** Each report records which dataset it
ran (`report.dataset.file`). The Datasets tab groups runs by dataset and shows a
score sparkline, per-run deltas, and the total change across the series — click
any run to open its report. Re-run the same dataset after a model/guardrail
change to see the score move.

Server endpoints: `GET /api/datasets`, `POST /api/datasets/generate`,
`GET /api/eval-runs` (trends grouped by dataset).

## Findings → dataset (regression flywheel)

Every confirmed compromise can become a permanent regression test. On a report,
open a finding with verdict PASS/PARTIAL and click **Save as regression test** —
the exact attack (category, prompt, success criteria) is appended to
`data/datasets/regression/promoted.json` (deduped, fail-closed validated). Point
a scan's `customAttacksFile` at that set to re-test every past breach on each
run. This is the white-box flywheel: every eval makes the next dataset stronger.

Endpoint: `POST /api/datasets/promote` (admin).

## Two kinds: security vs functional quality

Datasets come in two **kinds**, graded in opposite directions:

| | `security` (default) | `quality` |
|---|---|---|
| Row asks | an attack | a legitimate task |
| Key fields | `category`, `prompt`, `successCriteria` | `task`, `input`, `reference` / `expectedTools`, `metric` |
| Success = | target compromised → **bad** | output matches reference → **good** |
| Runs on | the red-team engine (`customAttacksFile`) | a **quality scorer** (correctness judge / NeMo Evaluator) |

Set `kind` in the preset. Quality presets: `configs/datasets/nemo-mcp-quality.preset.json`,
`nemo-agent-quality.preset.json` (task pools + metrics like `tool_call_accuracy`,
`goal_accuracy`, `faithfulness`). In the Datasets tab, the **Kind** toggle picks
which to generate; quality datasets are written under `data/datasets/quality-<family>/`.

```bash
npm run gen:dataset -- --preset configs/datasets/nemo-agent-quality.preset.json \
  --out data/datasets/quality-agent/v1.json --count 300
```

### Running a quality dataset (native correctness scorer)

Quality datasets run on the **native correctness scorer** — not the security
engine. It sends each `input` to the target, extracts the response + tool calls,
and grades against the `reference`/`expectedTools`:

- **Deterministic metrics** (no LLM): `exact_match`, `f1`, `rouge`,
  `tool_call_accuracy`.
- **LLM-judge metrics** (reuses your judge model): `goal_accuracy`,
  `faithfulness`, `answer_relevancy`, `topic_adherence`, `context_recall`.

```bash
npm run eval:quality -- config.mytarget.json \
  --dataset data/datasets/quality-agent/v1.json \
  --threshold 0.7 --concurrency 4
```

It prints a live score, a per-metric / per-task breakdown, and writes a
`report/quality-report-*.json`. The dataset defaults to the config's
`customAttacksFile` if `--dataset` is omitted. Quality rows are kept out of the
security scan picker so the two axes never cross wires.

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
