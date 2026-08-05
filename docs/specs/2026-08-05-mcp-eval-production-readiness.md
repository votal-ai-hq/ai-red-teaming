# MCP Eval Dataset Generation: Findings and Next Changes

**Date:** 2026-08-05  
**Scope:** MCP quality and security dataset generation  
**Change type:** Decision document only. No runtime behavior is changed.

## Summary

The generated MCP datasets are useful for exploration, but they are not ready
to be used as release gates.

The main problem is not JSON formatting. The main problem is that a generated
row can look valid while being factually wrong:

- it can name the wrong tool;
- it can use a role that is not sent to the MCP server;
- it can refer to data that does not exist;
- it can expect an allowed action to be denied;
- it can score only the tool name while ignoring wrong arguments and failures;
- it can depend on state changed by an earlier row.

Generated rows should therefore be treated as **candidates**. A row becomes a
trusted regression case only after it passes target-aware validation and a
non-destructive preflight.

## What Was Reviewed

The assessment used executable code and observed behavior:

- current dataset generation, validation, MCP execution, and scoring code;
- generated Voyager quality and security datasets;
- live, non-destructive calls to Voyager;
- live discovery and scans through the Votal SAST MCP server;
- targeted automated tests;
- TypeScript typecheck and Voyager build.

No existing draft specification was used as a source.

## Current Result

| Area | Result | Reason |
|---|---|---|
| Security dataset | Not ready | The reviewed 8 rows do not satisfy the current native MCP execution contract. |
| Quality dataset | Not ready | All 8 rows pass structural validation, but several references contradict the target. |
| Role testing | Not reliable | A row's role does not automatically become the credential/header used by the MCP session. |
| Tool scoring | Not reliable | Tool-name matching does not verify arguments, tool errors, output, or state changes. |
| Repeatability | Not reliable | Stateful tools run without per-case reset or rollback. |
| Reproducibility | Not reliable | Random seed, prompt revision, target manifest hash, and fixture version are not recorded. |

## Confirmed Examples

### Quality rows

1. Two rows claim unrelated generated email addresses own Voyager bookings
   BK-7001 and BK-7002. Live Voyager returned no bookings for the generated
   address.
2. One row says a traveler cannot use add_traveler. Live Voyager allowed the
   traveler through authorization and failed only because a non-existent test
   booking was supplied.
3. One row uses travel:write, which is a scope, as the expected tool name.
4. One row expects a booking for non-existent flight FL-3001 to succeed.
5. One row searches a 2023 date while the current fixture contains 2026 travel
   data.

The validator accepts these rows because it checks that the fields are present,
not that the reference is true.

### Security rows

1. All 8 reviewed rows are missing the native execution fields required by the
   current MCP validator.
2. A create_booking row is graded on whether cancel_booking or
   override_price succeeded.
3. An authorized admin operation is described as a cross-tenant compromise.
4. Several rows put transport fields such as X-User-Role inside tool
   arguments even though those fields are not in the tool schema.
5. Some categories require multiple calls or an agent, but the generated
   security row supports only one direct operation.

These rows should be quarantined rather than shown as runnable regression data.

## Why This Happens

### 1. Independent random sampling

Category, role, strategy, severity, tool, task, and metric are sampled
independently. There is no rule proving that the combination makes sense.

Examples:

- cross-tenant testing against a tool with no tenant-owned identifier;
- shell injection against a schema with only constrained numbers;
- parameter extraction scored only by tool name;
- tool-chain attacks represented as one direct call.

### 2. The model writes its own expected result

The same generation flow creates both the test input and its expected result.
It does not check the expected result against live target data, authorization
rules, or fixture state.

### 3. The quality row cannot describe the real expectation

The current row stores:

- input text;
- a free-text reference;
- expected tool names;
- one metric.

It cannot store expected arguments, call order, accepted errors, output checks,
state changes, setup, or cleanup.

### 4. The row role is not the wire identity

MCP requests use the static headers in the scan configuration. Sampling
guest, traveler, or admin in a row does not switch the actual session
credential.

### 5. Stateful cases share data

Booking creation, coupon, payment, refund, cancellation, and price changes can
affect later rows. Concurrent execution makes the result order-dependent.

## Required First Changes

Keep the implementation work split into small pull requests. The first five
changes provide the minimum trustworthy path.

### Change 1: Capture a target contract

Before generation, save a versioned snapshot containing:

- MCP server and protocol version;
- capabilities;
- tool names and input schemas;
- prompts and resources;
- tool risk classification;
- non-secret credential profile IDs;
- fixture version;
- authorization and tenant rules;
- manifest hash.

Every generated row must reference this contract hash.

### Change 2: Compile only valid combinations

Replace independent sampling with simple compatibility rules.

Examples:

- cross-tenant requires two tenant identities and a tenant-owned fixture;
- authorization bypass requires at least two credential profiles;
- injection requires a schema field that can carry the payload;
- tool-chain attacks require agent/multi-step execution;
- server-direct cases cannot use agent-only categories.

Unsupported categories should be reported as coverage gaps, not filled with
invented cases.

### Change 3: Validate the full quality outcome

Replace expected tool-name strings with structured expectations:

    {
      "expectedCalls": [
        {
          "tool": "apply_coupon",
          "arguments": {
            "bookingId": "BK-7002",
            "code": "WELCOME10"
          }
        }
      ],
      "expectedToolError": false,
      "forbiddenTools": ["override_price"],
      "outputAssertions": [],
      "stateAssertions": []
    }

The score must separately report:

- tool selection;
- argument correctness;
- call order;
- tool outcome;
- final answer;
- resulting state.

Calling the correct tool with wrong arguments must not receive full credit.

### Change 4: Bind rows to credential profiles

Each row must name a non-secret credential profile. The runtime must create the
MCP session from that profile.

The trace should record the profile ID, role, tenant, and scopes without
recording the secret.

### Change 5: Isolate state

Each case needs:

- known setup data;
- a fresh tenant, transaction, snapshot, or disposable server;
- state assertions;
- cleanup or rollback.

Scored runs must not repair generated arguments with an LLM. Argument repair is
allowed only during candidate preparation, before the dataset is approved.

## Separate the Four Scores

Do not publish one ambiguous MCP score.

| Mode | What it measures |
|---|---|
| Server quality | Direct MCP protocol, schema, output, errors, state, latency, and compatibility. |
| Agent quality | Natural-language task, tool selection, arguments, plan, and final answer through an agent. |
| Server security | Authentication, authorization, tenant isolation, validation, data exposure, mutation, and rate limits. |
| Agent security | Metadata poisoning, tool-output injection, shadowing, rug pull, consent bypass, and multi-tool attacks. |

This prevents an agent choosing the wrong tool from being reported as a server
failure, and prevents a server error from being counted as successful tool
selection.

## Production Dataset Gate

A dataset can be marked production only when:

1. Every row references a target contract and fixture version.
2. Every tool, prompt, and resource exists in the captured manifest.
3. Every argument validates against the captured schema.
4. Every row uses an effective credential profile.
5. Setup and cleanup pass in a disposable environment.
6. Expected results are deterministic or explicitly approved.
7. Positive and negative controls produce opposite expected results.
8. No row is silently skipped or repaired during scoring.
9. Five clean-state runs vary by no more than 2 percentage points.
10. No secret is stored in a dataset, trace, report, or prompt.
11. Windows and Linux tests pass.
12. Manifest drift blocks the run until the dataset is revalidated.

Rows that cannot execute should be reported as INVALID_CASE, not secure,
failed, or defended.

## Prioritized Backlog

| Priority | Change | Done when |
|---|---|---|
| P0 | Rotate the exposed SAST credential. | The old credential is revoked and absent from stored artifacts. |
| P0 | Quarantine schema-less datasets. | Stale rows cannot appear runnable. |
| P0 | Add the target contract and hash. | Every approved row is bound to one target snapshot. |
| P0 | Add credential profiles. | The row identity matches the identity sent on the wire. |
| P0 | Add state reset and cleanup. | Repeated and parallel runs do not affect each other. |
| P0 | Add structured quality and security expectations. | Wrong arguments, errors, and state changes are scored correctly. |
| P0 | Split server and agent evaluation modes. | Reports attribute failures to the correct layer. |
| P1 | Validate arguments with JSON Schema. | Invalid calls fail before a scored run. |
| P1 | Add compatibility rules. | Impossible task/category/tool combinations are not generated. |
| P1 | Remove evaluation-time argument repair. | The executed row is identical to the approved row. |
| P1 | Record generation provenance. | Seed, model, prompt hash, manifest hash, and fixture version are present. |
| P1 | Normalize dataset paths. | Dataset listing and containment tests pass on Windows and Linux. |
| P1 | Add semantic duplicate detection. | Paraphrased duplicates are reported and controlled. |
| P1 | Harden metadata and provider boundaries. | Tool metadata cannot steer generation and sensitive context follows egress policy. |

## Verification Performed

- npm run typecheck: passed.
- Voyager npm run build: passed.
- Targeted MCP and dataset tests: 177 passed, 2 failed.
- Both failures are existing Windows path-normalization failures in dataset
  listing.
- Reviewed security artifact: 0 of 8 accepted by the current native MCP
  validator.
- Reviewed quality artifact: 8 of 8 structurally accepted despite the semantic
  issues listed above.
- Live MCP calls were non-destructive.
- Two live SAST scans returned no source-code findings. This confirms that SAST
  is useful for implementation defects but does not validate eval correctness.

## Delivery Order

1. Credential rotation and stale dataset quarantine.
2. Target contract, JSON Schema validation, and credential binding.
3. Structured quality scoring and state isolation.
4. Security compatibility rules and deterministic controls.
5. Agent-mediated evaluation modes.
6. Provenance, drift handling, repeatability, and promotion workflow.

The first production milestone should be a small deterministic server-quality
dataset for Voyager. Security generation and agent-mediated scoring should be
enabled as release gates only after the same contract, identity, state, and
oracle controls are in place.
