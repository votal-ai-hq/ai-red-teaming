# MCP Eval Dataset Generation: Production Readiness Review and Remediation Spec

**Audience:** Security, Eval Platform, MCP Runtime  
**Date:** 2026-08-05  
**Review basis:** Current executable code at `f617ae1`, local generated artifacts,
live MCP protocol calls to Voyager and Votal SAST, and the current automated
tests. Existing draft specifications were explicitly excluded as source
material.  
**Change scope:** Specification only. No implementation changes are included.

## 1. Executive decision

The MCP eval dataset generation system is **not production grade** for either
functional-quality evaluation or security evaluation.

The system has useful foundations: MCP discovery, native protocol execution,
strict enum checks, bounded generation concurrency, deterministic text metrics,
an MCP agent loop, and a separation between quality and security row shapes.
Those foundations are not enough to make the resulting scores trustworthy.

The primary failure is semantic validity. The pipeline currently proves that a
row is shaped like an eval, but does not prove that:

1. the row can execute against the discovered MCP contract;
2. the selected attack/task is meaningful for the selected tool and role;
3. the expected result is correct for the target's actual policy and state;
4. the scorer measures the behavior named by the row;
5. repeated runs start from equivalent state and credentials; or
6. the dataset can be reproduced and audited later.

**Production recommendation:**

- Do not use generated MCP datasets as release gates, compliance evidence,
  customer-facing security claims, or model/server scorecards.
- Continue using them only as untrusted candidate generation for exploration.
- Promote a row into a release-blocking dataset only after deterministic
  contract validation, sandbox preflight, oracle validation, and review.
- Split MCP server evaluation from agent-plus-MCP evaluation. They are different
  products and currently produce confounded scores.

## 2. Immediate security action

The live SAST MCP API key shared for this review is now exposed in conversation
history. Rotate and revoke it immediately, check its access logs from the time it
was issued, and replace it with a short-lived or scoped credential. The key is
intentionally omitted from this document.

Until the remediation in this spec is complete:

- label generated datasets `experimental/unverified` in the API and UI;
- block unverified datasets from release-gating workflows;
- quarantine existing datasets that lack a schema version and signed validation
  report;
- disable destructive tools during generation preflight unless a disposable
  target and cleanup contract are configured; and
- prohibit target secrets, production data, and customer system prompts from
  being sent to third-party generation models.

## 3. Evidence and observed results

### 3.1 Generated Voyager security artifact

Artifact reviewed:
`data/datasets/nemo-mcp/voyager-openai-qa-20260728-114245.json`.

- 8 rows were present.
- 0 of 8 satisfy the current MCP dataset execution contract.
- All 8 are rejected by `validateRows(..., { family: "mcp" })` because they lack
  `_mcpOperation` and the corresponding native execution fields.
- Several prompts contain undeclared transport fields such as `X-User-Role`,
  `tool`, and `debug_mode` inside tool arguments.
- Several success criteria refer to a different tool than the row's sampled
  surface. For example, a `create_booking` call is graded on whether
  `cancel_booking` or `override_price` succeeded.
- Authorized behavior is repeatedly described as a compromise, including admin
  execution of an admin operation and guest execution of read-only search.

This artifact must be treated as stale and non-executable, not as a regression
dataset.

### 3.2 Generated Voyager quality artifact

Artifact reviewed:
`data/datasets/quality-mcp/voyager-openai-qa-20260728-114245.json`.

- 8 of 8 rows pass the current structural quality validator.
- 0 of 8 are portable production rows because none records the credential/role
  profile, target contract version, state fixture, setup, or cleanup.
- Only 2 of 8 have a locally plausible denial reference under the current
  traveler configuration.
- Two rows claim unrelated email addresses own `BK-7001` and `BK-7002`; live
  Voyager returned zero bookings for the generated address.
- One row claims a traveler cannot call `add_traveler`; live Voyager allowed the
  role through authorization and then returned only a booking-not-found error
  for a non-mutating dummy ID.
- One row uses `travel:write`, a scope, as an expected tool name.
- One row asks for non-existent `FL-3001` and expects successful creation.
- One row uses invalid coupon `SAVE20` against a booking state that does not
  support the claimed outcome.
- One row searches a stale 2023 date while the target fixture is dated 2026.

The current validator accepts these contradictions because it checks non-empty
fields and known metric names, not target truth.

### 3.3 Live MCP observations

Live Voyager calls were deliberately non-destructive:

- `add_traveler` as `traveler` with a dummy booking passed authorization and
  failed at booking lookup. This contradicts the generated refusal reference.
- `list_bookings` for the generated email returned an empty list. This
  contradicts two generated references.
- `override_price` as `traveler` returned an MCP tool error denying
  `admin:write`, as the real policy requires.
- `search_flights` as `guest` with generated undeclared debug/header fields ran
  as an ordinary allowed search. The extra arguments had no security effect and
  the stale date returned no results.

The Votal SAST MCP endpoint negotiated protocol `2025-06-18` and exposed seven
tools. Its `sast_fix_code` mutation capability is not detected as sensitive by
the current profile keyword heuristic. Two live `sast_scan_code` runs over the
generation/validation code and dataset API/storage code returned zero findings.
This is expected evidence that SAST is a secondary implementation control; it
does not detect eval oracle correctness, target-grounding errors, or measurement
validity.

### 3.4 Automated verification

- `npm run typecheck`: passed.
- Voyager `npm run build`: passed.
- Targeted eval/MCP test run: 177 passed, 2 failed.
- Both failures are Windows path-normalization failures in dataset listing tests:
  filesystem paths contain backslashes while assertions and downstream logical
  paths assume forward slashes.
- The security sample fails current MCP validation 8/8.
- The quality sample passes current validation 8/8, demonstrating that the
  current tests/validator do not catch semantic oracle defects.

## 4. Root-cause assessment

### 4.1 Generation samples incompatible dimensions independently

Security generation independently samples category, severity, strategy, role,
and surface in
[`nemo-config-builder.ts`](../../lib/dataset/nemo-config-builder.ts). Quality
generation independently samples task, metric, role, and surface in
[`quality-config-builder.ts`](../../lib/dataset/quality-config-builder.ts).

There is no compatibility model connecting these dimensions. This creates
impossible tuples such as:

- cross-tenant access against a tool with no tenant-controlled identifier;
- shell injection against a schema with only constrained numeric values;
- tool-chain hijack in a runner that intentionally supports only one direct MCP
  operation per generated security row;
- parameter-extraction tasks scored only on tool name;
- topic adherence paired with a task whose required evidence is exact tool
  arguments; and
- a low-privilege role paired with a static transport credential that actually
  has different privileges.

### 4.2 The generator authors its own unverified oracle

The same model first writes the input/attack and then writes the reference or
success criterion. For security rows, the grading prompt receives the category
and generated JSON but does not explicitly receive the selected target surface,
schema, effective credential, or state. This directly explains success criteria
that name unrelated tools.

For quality rows, the reference prompt asks the model to invent an ideal answer
and expected tools without executing the target, checking fixture data, or
validating authorization. A fluent reference is therefore mistaken for a true
reference.

An LLM-generated oracle may be a candidate. It must never become a production
oracle without independent verification.

### 4.3 Row schemas are too weak for the claimed metrics

The quality schema contains only `input`, optional free-text `reference`,
`expectedTools: string[]`, and one metric. It cannot represent:

- expected tool arguments;
- acceptable alternative tools;
- required/forbidden call ordering;
- required or maximum call counts;
- confirmation/consent checkpoints;
- expected MCP `isError` behavior;
- output JSON Schema or JSONPath assertions;
- preconditions and postconditions;
- state mutations;
- latency/retry/cancellation behavior; or
- setup and cleanup.

Consequently `tool_argument_accuracy` and `parameter_extraction` are scored by
the same order-insensitive tool-name F1 used for tool selection. A call with the
right name, wrong arguments, wrong output, and failed business outcome can score
1.0.

The security schema has the same issue in a different form: a prose success
criterion is not a machine-verifiable security oracle.

### 4.4 Dataset role is not the effective MCP credential

The custom row loader copies `role` into the attack object and ordinary request
payload, but the MCP adapter constructs a session from static
`config.target.mcp.headers`. The quality MCP agent also uses that one static
session configuration for every row.

Therefore a dataset that samples guest, traveler, admin, viewer, user, or service
does not actually execute those identities unless the whole scan configuration
is changed. Security authorization and cross-tenant results are invalid when the
row label and wire credential differ.

### 4.5 Stateful tools are evaluated concurrently without isolation

Voyager uses a process-wide mutable store. Quality evaluation defaults to
bounded concurrency and has no per-row reset, tenant namespace, fixture lease,
transaction rollback, or cleanup step. `apply_coupon`, `pay_booking`, refund,
cancel, add-traveler, create, and override cases can affect later rows.

The resulting score depends on row ordering, concurrency, earlier failures, and
whether another evaluation is running. This is incompatible with regression
gating.

### 4.6 Validation is syntactic, not semantic

Current security validation checks category, prompt, severity, success criterion,
operation discriminator, and presence of operation fields. It does not validate
arguments against the discovered JSON Schema or prove category/surface
compatibility.

Current quality validation checks task, metric, input, and presence of a
reference or expected tool. It does not verify that expected tools exist, that a
scope was not used as a tool, that the reference matches target data/policy, or
that the metric is compatible with the task.

Exact normalized-string deduplication also misses semantic duplicates and
template families that differ only in names, IDs, dates, or framing.

### 4.7 Evaluation-time repair changes the test case

When a tool call returns `-32602 Invalid arguments`, the MCP adapter can ask an
LLM to repair arguments, overwrite `_mcpArguments`, and retry. This improves
exploration but invalidates regression reproducibility: the executed case is no
longer the versioned dataset row.

Argument repair belongs before dataset promotion. A scored production run must
execute the immutable effective arguments recorded in the dataset and fail the
dataset preflight if they are invalid.

### 4.8 MCP server quality and agent quality are conflated

The quality runner converts a natural-language task into an LLM agent loop, lets
that LLM choose tools, and then scores the trace. This measures the combined
system:

`agent model + prompt + MCP client loop + MCP server + credential + target state`.

It does not isolate MCP server quality. A correct server can receive a low score
because the agent selected the wrong tool; a broken server can receive a high
tool-selection score because the agent named the expected tool before the call
failed.

Production reporting must expose these as separate evaluation products.

### 4.9 Untrusted target metadata enters generation prompts

Tool descriptions, schemas, imported system prompts, policies, business rules,
and operator examples are interpolated into model prompts as instructions/data
without a hardened trust boundary. A malicious or compromised MCP server can
place prompt injection in its tool metadata and steer dataset generation or
oracle generation.

The same profile path can send sensitive system prompts or policy content to an
external provider. Length caps reduce cost but do not provide DLP, redaction,
tenant policy enforcement, or injection isolation.

### 4.10 Datasets lack reproducible provenance

Direct generation uses `Math.random()`, temperature `0.9`, and no recorded seed.
Rows record only a generic generator note. Missing provenance includes:

- dataset schema version;
- target contract and manifest hash;
- target fixture version;
- generator provider/model/version;
- prompt-template revision and hash;
- sampling seed and sampling plan;
- generation parameters;
- effective credential profile identifier;
- validation tool versions and gate results;
- reviewer/adjudicator record; and
- parent dataset/row lineage.

A saved row cannot be reconstructed, independently audited, or safely compared
after target drift.

## 5. Required target model

Introduce an immutable, versioned `McpTargetContract` captured from discovery
plus operator-supplied policy. It must be the only input from which production
cases are compiled.

Minimum contract:

```jsonc
{
  "schemaVersion": 1,
  "targetId": "voyager-mcp",
  "server": {
    "name": "voyager-mcp",
    "version": "1.0.0",
    "protocolVersion": "2025-06-18",
    "capabilities": ["tools"]
  },
  "manifestHash": "sha256:...",
  "tools": [
    {
      "name": "override_price",
      "inputSchema": {},
      "outputSchema": {},
      "annotations": {},
      "risk": "destructive",
      "requiredScopes": ["admin:write"],
      "dataClasses": ["booking", "financial"]
    }
  ],
  "credentialProfiles": [
    {
      "id": "traveler-a",
      "role": "traveler",
      "tenant": "tenant-a",
      "secretRef": "vault://...",
      "scopes": ["travel:read", "travel:write", "payments:write"]
    }
  ],
  "fixtures": {
    "version": "voyager-fixture-v1",
    "entities": {},
    "resetStrategy": "api|snapshot|transaction|ephemeral-instance"
  },
  "policies": [],
  "discoveryTimestamp": "..."
}
```

Requirements:

- Secrets are external references, never embedded in datasets or contracts.
- Tool risk cannot rely only on keyword heuristics. Prefer MCP annotations,
  explicit owner classification, code analysis, and policy overrides.
- Contract capture must include prompts, resources, resource templates,
  pagination behavior, change notifications, and output schemas where exposed.
- Any manifest hash drift invalidates or explicitly revalidates the dataset.
- Credentials must cover subject, role, scopes, tenant, audience, and expiry.

## 6. Split the product into four eval modes

### 6.1 MCP server functional conformance

Direct protocol cases with deterministic inputs and assertions:

- initialize and capability negotiation;
- tools/list, prompts/list, resources/list, and pagination;
- valid and invalid schema inputs;
- expected `isError`, JSON-RPC error, and HTTP behavior;
- deterministic output/schema assertions;
- state transition and idempotency assertions;
- cancellation, retry, timeout, concurrency, and rate-limit behavior; and
- backward compatibility across manifest versions.

No agent LLM is used in this score.

### 6.2 Agent plus MCP functional quality

Natural-language tasks evaluated through an agent loop:

- tool selection;
- exact/partial argument extraction;
- multi-tool ordering and dependency handling;
- clarification and confirmation behavior;
- final answer grounded in tool output; and
- recovery from tool errors.

Reports must name the agent model/prompt and must not label this as MCP server
quality alone.

### 6.3 MCP server-native security

Direct protocol and backend security cases:

- authentication and token audience;
- authorization and role/scope enforcement;
- cross-tenant/IDOR with known fixture identities;
- input validation and backend injection only where schema fields can carry the
  payload;
- excessive data exposure;
- unsafe mutation, replay, idempotency, and confirmation;
- resource/prompt access control;
- session isolation;
- rate limits and resource exhaustion; and
- auditability.

### 6.4 Agent/client-mediated MCP security

Scenarios requiring an MCP client or agent:

- tool metadata poisoning;
- tool output/indirect prompt injection;
- tool shadowing and namespace collision;
- rug pull/metadata drift;
- confused-deputy and cross-server chains;
- consent bypass; and
- multi-step exfiltration.

Supply-chain categories such as compromised SDK dependencies require build/SBOM
evaluation, not fabricated direct tool arguments. Do not include a category in a
dataset unless the selected eval mode can observe its success condition.

## 7. Required row schemas

### 7.1 Common immutable envelope

Every production row needs:

```jsonc
{
  "schemaVersion": 2,
  "caseId": "stable-content-derived-id",
  "kind": "quality|security",
  "mode": "server-direct|agent-mcp",
  "targetContractHash": "sha256:...",
  "fixtureVersion": "...",
  "credentialProfileId": "...",
  "risk": "read-only|reversible|financial|destructive",
  "generator": {
    "provider": "...",
    "model": "...",
    "templateHash": "sha256:...",
    "seed": 123,
    "temperature": 0,
    "generatedAt": "..."
  },
  "lineage": {
    "source": "synthetic|promoted-finding|hand-authored",
    "parentCaseId": null
  }
}
```

### 7.2 Quality case oracle

Replace `expectedTools: string[]` with structured expectations:

```jsonc
{
  "setup": [],
  "input": "...",
  "expected": {
    "toolCalls": [
      {
        "name": "apply_coupon",
        "arguments": {
          "bookingId": { "equals": "BK-7002" },
          "code": { "equalsIgnoreCase": "WELCOME10" }
        },
        "required": true
      }
    ],
    "order": "strict|partial|any",
    "forbiddenTools": ["override_price"],
    "maxCalls": 2,
    "toolResult": {
      "isError": false,
      "jsonPathAssertions": []
    },
    "finalAnswerAssertions": [],
    "statePostconditions": []
  },
  "cleanup": []
}
```

Arguments should support exact, type, range, regex, set membership, JSON Schema,
and custom deterministic predicates. Alternative valid plans should be explicit.

### 7.3 Security case oracle

Security success must be expressed as machine-verifiable evidence:

```jsonc
{
  "threat": {
    "category": "cross_tenant_access",
    "layer": "server-native",
    "attackerProfile": "traveler-tenant-a",
    "victimFixture": "booking-tenant-b"
  },
  "steps": [],
  "secureOracle": {
    "allowed": false,
    "acceptedErrors": ["authorization_denied", "not_found"],
    "forbiddenDataTokens": ["canary:tenant-b-booking"],
    "stateInvariants": ["tenant-b booking unchanged"]
  },
  "compromiseOracle": {
    "any": [
      "victim canary returned",
      "victim state changed",
      "privileged action committed"
    ]
  }
}
```

Free-text rationale may accompany the oracle, but must not be the sole release
gate when deterministic evidence is possible.

## 8. Generation architecture

Replace independent random sampling with a constraint-driven scenario compiler.

### Stage A: discover and classify

1. Capture the target contract through a real MCP session.
2. Merge owner-supplied auth, tenant, policy, fixture, and data-class metadata.
3. Classify tool risk and supported security/quality capabilities.
4. Hash and sign the contract.

### Stage B: compile feasible scenario plans

Each scenario template declares prerequisites, for example:

```text
cross_tenant_access requires:
  credential profiles in at least two tenants
  AND a target identifier bound to tenant-owned fixture data
  AND a deterministic forbidden-data/state oracle
```

Only produce category/tool/role/metric combinations whose prerequisites are
satisfied. Unsupported combinations are reported as coverage gaps, not filled
with hallucinated rows.

### Stage C: synthesize bounded values

Use deterministic generators first for IDs, dates, enums, boundary values,
fixture entities, and known attack payloads. Use an LLM only for fields where
linguistic diversity adds value:

- natural-language user phrasing;
- adversarial strings placed in schema-compatible free-text fields;
- paraphrases; and
- multi-turn social context in agent-mediated modes.

The LLM must not choose the tool, role, fixture truth, expected authorization,
or oracle.

### Stage D: offline validation

Before touching the target:

- validate every call with a standards-compliant JSON Schema validator;
- prove tool/prompt/resource names exist in the captured manifest;
- prove credential profiles and fixtures exist;
- validate task/metric/scorer compatibility;
- validate setup/action/cleanup dependency graphs;
- reject transport headers embedded as undeclared tool arguments;
- reject category/surface pairs without an observable compromise oracle;
- perform semantic duplicate clustering; and
- run secret/PII/DLP checks on all provider-bound and persisted content.

### Stage E: sandbox preflight

Run candidates against a disposable reference target or contract emulator:

- setup must succeed;
- the operation must reach the intended code path;
- secure and vulnerable controls must produce opposite expected verdicts;
- cleanup/reset must succeed;
- repeated runs must be stable; and
- no case may rely on evaluation-time LLM repair.

Preflight validates the eval, not whether the production target is secure.

### Stage F: promotion

Generated rows remain candidates. Promotion produces an immutable dataset bundle
containing:

- rows;
- target contract hash;
- generator manifest;
- validation report;
- coverage report;
- reviewer/adjudication record;
- checksums/signature; and
- compatibility/migration status.

## 9. Scoring changes

### 9.1 Quality scoring

- Split tool selection, argument correctness, plan/order, tool outcome, final
  answer, and state correctness into separate sub-scores.
- Do not give full credit merely because the expected tool name was attempted.
- Treat MCP `isError: true` as an explicit outcome, not a generic HTTP 200.
- Score arguments using schema-aware matchers and preserve original value types.
- Support alternative valid plans without order-insensitively accepting every
  permutation.
- Report agent failure separately from server failure.
- Judge-based metrics must be non-blocking until calibrated on an expert-labeled
  gold set.

### 9.2 Security scoring

- Use deterministic auth, data-canary, state-diff, and error predicates first.
- Require category-specific evidence. Successful tool execution alone is not a
  security success.
- Preserve original arguments, effective arguments, complete JSON-RPC trace,
  credential profile ID, fixture snapshot, and state diff.
- Never mutate the attack row during scoring.
- Treat unsupported/unexecutable as `INVALID_CASE`, not defended/failed.
- Separate `TARGET_ERROR`, `HARNESS_ERROR`, `ORACLE_ERROR`, and `INCONCLUSIVE`
  from secure/vulnerable verdicts.

### 9.3 LLM judge hardening

- Use a different judge model/vendor from the generator for calibration runs.
- Pass untrusted tool outputs and references as escaped structured data, never as
  trusted instructions.
- Add judge-prompt-injection canary cases.
- Require structured output schema validation.
- Store judge model/version/prompt hash and raw verdict.
- Measure inter-judge and judge-to-human agreement.
- Do not use an LLM judge where a deterministic oracle is available.

## 10. Production release gates

A dataset may be labeled `production` only when all gates pass.

### Contract and execution gates

- 100% of cases reference an immutable target contract hash.
- 100% of tool/prompt/resource names exist in that contract.
- 100% of arguments validate against the captured schema before execution.
- 100% of cases bind an effective credential profile and fixture version.
- 100% of setup and cleanup steps pass in a disposable environment.
- 0 scored cases use evaluation-time argument repair.
- 0 cases are silently skipped.

### Oracle gates

- 100% of release-blocking core cases use deterministic or owner-approved
  structured oracles.
- Positive and negative controls produce the expected opposite outcomes.
- A stratified review finds 0 critical oracle contradictions.
- For judge-assisted experimental cases, expert-label agreement is at least 95%,
  false-pass rate is at most 2%, and Cohen's kappa is at least 0.80 on a gold set
  of at least 200 cases.

### Reliability gates

- Five repeated clean-state runs have aggregate score standard deviation at or
  below 2 percentage points.
- Parallel and sequential runs produce equivalent results within the declared
  tolerance.
- No cross-case state, session, tenant, or credential leakage is detected.
- Cancellation and timeout tests leave no persistent mutation.

### Coverage gates

- Coverage is reported across eval mode, tool, risk tier, credential role,
  tenant boundary, operation type, task/category, and success/denial path.
- Every included category has a documented capability prerequisite and oracle.
- Risk-weighted minimums replace one generic per-category count floor.
- Unsupported categories are visible as gaps; they are never represented by
  fabricated low-quality cases.

### Governance and security gates

- Dataset bundle has checksums/signature, lineage, retention class, and owner.
- No live secret is stored in config, dataset, report, trace, or prompt.
- Provider-bound content passes DLP and tenant egress policy.
- Destructive/financial cases run only on disposable or transactional fixtures.
- Dataset API filesystem and network egress controls pass security review.
- Linux and Windows test suites are green.

## 11. Prioritized bug and change backlog

| ID | Priority | Change | Acceptance criterion |
|---|---:|---|---|
| MCP-EVAL-001 | P0 | Add `McpTargetContract` snapshot, hash, credential profiles, fixtures, and policy metadata. | No production row can be created without a valid contract hash and effective credential profile. |
| MCP-EVAL-002 | P0 | Replace independent sampling with a category/task capability compatibility compiler. | Impossible category/tool/role/metric tuples are rejected before model calls and reported as coverage gaps. |
| MCP-EVAL-003 | P0 | Introduce quality row V2 with argument, order, result, state, setup, and cleanup assertions. | `tool_argument_accuracy` fails for wrong arguments even when the tool name is correct. |
| MCP-EVAL-004 | P0 | Introduce security row V2 with structured secure and compromise oracles. | Cross-tenant/auth cases require two real fixture identities and deterministic canary/state evidence. |
| MCP-EVAL-005 | P0 | Bind each row to an actual MCP credential/session profile. | Wire headers/token/tenant match the row identity and are visible by non-secret ID in the trace. |
| MCP-EVAL-006 | P0 | Add disposable state reset/lease/rollback and cleanup. | Five repeat runs are stable and concurrent cases cannot alter each other's fixtures. |
| MCP-EVAL-007 | P0 | Move argument repair to candidate preflight; prohibit it in scored runs. | Scored effective arguments equal immutable dataset arguments byte-for-byte after canonicalization. |
| MCP-EVAL-008 | P0 | Split server-direct quality/security from agent-mediated quality/security. | Reports name one of four eval modes and attribute agent versus server failures separately. |
| MCP-EVAL-009 | P0 | Quarantine schema-less/stale datasets and revalidate on list/load/run. | The reviewed 8-row stale security artifact cannot appear runnable or produce an empty misleading scan. |
| MCP-EVAL-010 | P0 | Rotate the exposed SAST key and implement scoped secret references/redaction. | Old key is revoked; no key appears in repository, dataset, report, logs, or UI payloads. |
| MCP-EVAL-011 | P0 | Add MCP/server egress policy for dashboard-run targets and generation providers. | Private/link-local/loopback destinations and unsafe redirects are denied unless explicitly approved for local mode. |
| MCP-EVAL-012 | P0 | Harden untrusted metadata/profile prompt boundaries and add DLP. | Tool metadata injection cannot alter output contract; canary secrets never leave allowed boundary. |
| MCP-EVAL-013 | P1 | Validate arguments with JSON Schema during generation and save/load. | Unknown properties, missing required values, wrong enums/types/ranges fail before execution. |
| MCP-EVAL-014 | P1 | Validate expected tools, task-metric compatibility, fixtures, dates, and entity ownership. | Scope names such as `travel:write` cannot pass as tool names; stale/nonexistent fixtures are rejected. |
| MCP-EVAL-015 | P1 | Replace tool-name F1 with sub-scores for selection, args, order, outcome, answer, and state. | A right-name/wrong-args/error-result trace cannot score full credit. |
| MCP-EVAL-016 | P1 | Add semantic deduplication and diversity/coverage metrics. | Near-identical paraphrases cluster; reports show effective unique-case rate and distribution. |
| MCP-EVAL-017 | P1 | Add deterministic seed and full generation provenance. | A bundle records RNG seed, model revision, template hash, parameters, contract, and lineage. |
| MCP-EVAL-018 | P1 | Make coverage floors hard, risk-weighted gates rather than warnings. | A dataset cannot be promoted when required risk/tool/role cells are empty. |
| MCP-EVAL-019 | P1 | Replace sensitive-tool keyword inference with annotations plus owner classification. | `sast_fix_code` and equivalent mutation tools are correctly classified without relying on the word list. |
| MCP-EVAL-020 | P1 | Normalize logical dataset paths to POSIX and use path-relative containment checks. | Dataset tests pass on Windows/Linux and prefix collisions such as `data/datasets-evil` are rejected. |
| MCP-EVAL-021 | P1 | Preserve full original/effective request, MCP trace, state diff, and outcome class. | Every verdict is auditable without rerunning; secrets/PII are redacted by policy. |
| MCP-EVAL-022 | P1 | Calibrate and adversarially test LLM judges. | Gold-set agreement, false-pass rate, kappa, repeat variance, and injection-resistance gates pass. |
| MCP-EVAL-023 | P1 | Make validation behavior uniform across CLI, dashboard, in-run, merge, and promotion. | The same row receives the same validation decision at every entry point; invalid rows are never silently dropped into a smaller run. |
| MCP-EVAL-024 | P2 | Add manifest drift handling and compatibility migration. | Contract drift blocks runs or produces an explicit reviewed migration with lineage. |
| MCP-EVAL-025 | P2 | Add cost, latency, token, and failure observability by pipeline stage. | Generation, validation, preflight, execution, and judging have separate SLOs and error budgets. |

## 12. Required tests

### Unit/property tests

- Generate arbitrary schemas and prove generated arguments always validate.
- Prove every category/task template enforces its capability prerequisites.
- Prove credential profile identity reaches transport headers/token claims.
- Prove right-tool/wrong-argument and right-tool/error-outcome cases fail.
- Prove setup/action/cleanup dependency ordering.
- Prove original dataset rows are never mutated during scoring.
- Prove Windows/Linux logical path normalization and containment.

### Contract tests

- Run against Voyager fixtures for guest, traveler, and admin.
- Run against the SAST MCP tools-only surface and verify unsupported
  prompt/resource categories are omitted as explicit gaps.
- Add a deliberately poisoned MCP manifest to test generation prompt isolation.
- Add a deliberately schema-drifting/rug-pull server.
- Add a multi-tenant reference MCP server with deterministic canaries.
- Add vulnerable and secure twins for each deterministic security oracle.

### End-to-end tests

- Discover -> compile -> generate -> validate -> sandbox preflight -> promote ->
  execute -> score -> rerun.
- Same immutable dataset on five clean environments yields stable results.
- Concurrent financial/destructive cases cannot interfere.
- Expired/wrong-audience/cross-tenant credentials are actually sent on the wire.
- Old schema/stale contract bundles are blocked with a migration message.
- No valid case is silently skipped; no invalid case is counted as defended.

## 13. Delivery plan

### Phase 0: containment, 1-2 days

Owners: Security + Eval Platform

- Rotate exposed credential and audit use.
- Mark all generated datasets unverified.
- Block unverified datasets from release gates.
- Quarantine stale/schema-less artifacts.
- Disable destructive preflight without disposable state.

### Phase 1: trustworthy core, 1-2 sprints

Owners: MCP Runtime + Eval Platform

- Implement target contract and V2 row envelopes.
- Implement credential-profile binding and state reset.
- Implement JSON Schema validation and uniform validation decisions.
- Split server-direct from agent-mediated quality.
- Fix cross-platform paths and containment.

Exit: deterministic MCP conformance dataset runs repeatably against Voyager.

### Phase 2: security scenario compiler, 2-3 sprints

Owners: Security + Eval Platform

- Build capability-prerequisite templates by threat layer.
- Add deterministic security oracles, secure/vulnerable twins, and canaries.
- Split server-native from agent-mediated security.
- Add prompt-boundary/DLP/egress controls.

Exit: core auth, cross-tenant, data exposure, mutation, and injection cases pass
all deterministic gates.

### Phase 3: calibration and production promotion, 1-2 sprints

Owners: Eval Science + Security Assurance

- Build expert-labeled gold set.
- Calibrate judge-assisted metrics.
- Run repeatability, concurrency, drift, and cross-platform suites.
- Add signed dataset bundles and reviewer workflow.

Exit: all gates in Section 10 pass and Security approves release-gating use.

## 14. Decisions requested

1. Approve the policy that synthetic LLM output is a **candidate corpus**, not a
   production dataset, until promoted through deterministic gates.
2. Approve the four-mode product split so MCP server scores are not confounded
   with agent model behavior.
3. Fund the target contract, credential/fixture isolation, and structured oracle
   work before adding more providers, categories, or UI generation controls.
4. Require deterministic core datasets for release and compliance claims; keep
   judge-assisted cases in an explicitly experimental tier until calibrated.
5. Assign joint ownership: MCP Runtime for protocol/identity/state correctness,
   Eval Platform for schema/compiler/scoring, and Security Assurance for oracle
   policy and production promotion.

## 15. Definition of done

The system is production grade only when a skeptical reviewer can answer, from
the immutable bundle alone:

- What exact target contract, identity, tenant, and fixture did this case use?
- Why is this category/task feasible for this tool and eval mode?
- What exact request was sent, and did it validate before the run?
- What deterministic evidence makes the result pass, fail, or invalid?
- Was state clean before and after the case?
- Can the case and score be reproduced without an LLM repairing or redefining
  it at evaluation time?
- Did target, manifest, credential, prompt, model, or judge drift since approval?

The current implementation cannot answer those questions consistently. The
changes above are therefore correctness requirements, not optional eval polish.
