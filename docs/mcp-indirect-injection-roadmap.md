# MCP indirect prompt injection — coverage & roadmap

Audit of the MCP scanner against the OWASP indirect-prompt-injection testing
guide, plus the design for the remaining gaps.

## Architecture context

The scanner is a **direct MCP client**: `lib/target-adapter.ts` dispatches one
MCP operation per attack (`discover` / `tools/call` / `resources/read` /
`prompts/get`) and `lib/response-analyzer.ts` grades the returned JSON. There is
**no model-in-the-loop** deciding tool calls from retrieved content. This shapes
what is and isn't testable: we can exercise the MCP *server* surface directly,
but not "does an agent, once manipulated, chain into an unauthorized write."

## Coverage status

| Guide requirement | Status | Notes |
|---|---|---|
| #9 Tool-metadata poisoning | ✅ Full-schema | `lib/mcp/metadata-poisoning.ts` scans **every** schema field (descriptions, parameter names/defaults/required arrays, non-standard keys, server instructions) with a research-backed signal set (hidden `<IMPORTANT>` tags, `~/.ssh/id_rsa` exfil targets, concealment directives, imperative "before using this tool"). Grounded in Invariant Labs / CyberArk FSP / OWASP MCP03:2025. |
| MCP namespace collision / shadowing | ✅ New module | `mcpToolShadowingModule` + `scanToolShadowing`: cross-tool redirect directives, duplicate/near-duplicate names, tool-name squatting (Invariant shadowing PoC, OWASP MCP09:2025). |
| Insecure output handling / ATPA | ✅ New module | `mcpInsecureOutputModule` + `scanToolResultInjection`: inspects tool **results** for fabricated errors demanding secrets and injected instructions (CyberArk ATPA, OWASP LLM01). |
| Token audience / confused-deputy | ✅ New module | `mcpAuthAudienceModule` + `lib/mcp/auth-probe.ts` + `auth_probe` op: presents absent / invalid / wrong-audience (RFC 8707) credentials and grades acceptance as a vulnerability (MCP authorization spec MUST-reject / HTTP 401). Network transports only. Enable via the `tool_permission_escalation` category. |
| Rug-pull / sleeper mutation | ✅ New module | `mcpRugPullModule` + `diffMcpMetadata` + `rug_pull_probe` op: loads `tools/list` twice and diffs metadata; new poisoning on a later load → PASS, benign drift → PARTIAL (Invariant sleeper PoC, OWASP MCP03 rug-pull). Enable via `mcp_server_compromise`. |
| #4 Grade on execution trace | ✅ Partial | `analyzeMcpTrace` grades on the wire transcript; flags cross-tool chaining (a single-tool attack that invoked additional tools). |
| #1/#4 Canary detection | ✅ Hook ready | `analyzeResponse` detects a planted `_canary` reflected in **server** output/trace. Seeding canaries into a controlled environment still needs the agent-in-the-loop mode below. |
| #2b Tool-output injection | ⚠️ Detect-only | Detects injection strings served by the server; cannot confirm an orchestrator would act on them (no agent). |
| #2a/#2c/#2d Document / email / web-page channels | ❌ | No channel matrix; needs seeded content sources. |
| #2e Cross-tool read→write | ✅ Harness built | `analyzeMcpTrace` catches server-side chaining; model-driven chaining now covered by `agent-loop.ts` (write-after-poisoned-read). Pipeline wiring pending. |
| #3 Attack corpus × 8 channels | ⚠️ | Families exist; channel matrix not modeled. |
| #6 Argument provenance / taint | ✅ Harness built | `taintedArgKeys` in `agent-loop.ts` flags retrieval-sourced values reaching write arguments. Pipeline wiring pending. |
| #8 Approval-flow testing | ❌ | Needs agent mode with an approval gate. |

## Agent-in-the-loop MCP mode — status

**Core harness: implemented** in `lib/mcp/agent-loop.ts` (tested in
`tests/mcp-agent-loop.test.ts`). It drives an LLM that holds the MCP tools via a
portable ReAct/JSON protocol (the provider layer is text-only), seeds poisoned
content into a designated read tool's result, and grades the agent's own
tool-call trace against the OWASP fail conditions:

- **write-after-read** — a write/consequential tool invoked after the poisoned
  read (`classifyToolRisk` + `afterPoisonedRead`);
- **canary exfiltration** — the planted marker reaching an outbound argument;
- **argument taint (#6)** — a value lifted verbatim from retrieved content
  flowing into a write argument (`taintedArgKeys`).

The loop is dependency-injected (`chat`, `executeTool`) so it is unit-testable
without a live model or server; `runMcpAgentLoop` adapts a real provider +
`McpSession`.

**Wired into the run pipeline.** Enable per MCP target with
`target.mcp.agentLoop: true`. When set, round 1 builds agent-loop attacks from
the discovered tool surface (`buildAgentLoopAttacks`, one per read-tool carrier ×
injection template), dispatched through the new `agent_loop` MCP operation in
`lib/target-adapter.ts`. `analyzeMcpResponse` maps `compromised` → PASS/FAIL and
surfaces the behavioral findings; a genuine compromise is protected from the LLM
judge by the strong-evidence gate. The loop honors the engagement's
allow/deny tool scope — a blocked call is still recorded and graded (the attempt
proves the injection landed) but the destructive tool is never executed.

Channel matrix + provenance implemented: six attack families framed across
ingestion channels (document, tool_result, email, ticket, calendar, web_page),
capped via `maxAttacks` to bound token cost; grading now flags destination-taint
(retrieved content choosing a recipient/URL/path) and suppressed disclosure (a
write the agent hides from the user). Remaining polish: memory/database channels
and taint beyond verbatim-substring matching (e.g. transformed/encoded values).

## Proposal detail: the remaining gaps

The gaps that matter most — cross-tool chaining (#2e), write-triggered-by-content
(#2b), argument provenance (#6), and true canary seeding (#1) — all require the
same missing capability: a harness that drives an **LLM which holds the MCP
tools**, seeds attacker-controlled content into what a *read* tool returns, and
observes whether the model chains into a *write*.

### Shape

```
Attack config: agent-mcp mode
  ├─ scanner spins up (or points at) an LLM agent bound to the MCP tools
  ├─ scanner controls a "read" tool's return value (seeded poisoned content
  │   carrying an instruction + a unique canary)
  ├─ user-role prompt asks a benign task ("summarize the document")
  └─ scanner observes the full tool-call trace the agent produces
```

### New signals this unlocks

1. **Write-after-read (#2b, #2e)** — fail if a `write`-classed tool is invoked
   in the same turn whose trigger traces back to seeded content. `analyzeMcpTrace`
   already extracts the invoked-tool list; extend it with a read/write tool
   classification and a "caused-by seeded content" link.
2. **Argument provenance / taint (#6)** — tag every seeded value with its source
   (`untrusted_retrieval`) and fail when a tainted value flows into a
   consequential argument (recipient, URL, path). Enforce rules like
   "untrusted content may influence summary text but may not choose an email
   recipient." This is taint tracking for tool arguments.
3. **True canary (#1)** — seed `RT-CANARY-*` fake secrets into the agent's
   environment/context; the existing `_canary` detector in `analyzeResponse`
   already fails the test if the canary surfaces in an outbound argument. Only
   the *seeding* half is missing.
4. **Channel matrix (#2a/#2c/#2d, #3)** — parameterize the seeded content's
   carrier (document / email body / web page / DB record / tool result / memory)
   and run each attack family through every channel.

### Reuse from what already exists

- `McpExecutionTrace` + `analyzeMcpTrace` — trace extraction is done.
- `_canary` detection — done.
- `MCP_INJECTION_PATTERNS` + metadata scan — reused as the seeded-content corpus.
- The 8 fail-conditions from the guide become deterministic checks over the
  agent's tool-call trace.

### Non-goals / honesty

Canary *seeding* and provenance enforcement are only meaningful with an agent +
controlled environment. Against a black-box production MCP server the scanner
stays a server-surface scanner; that limitation is inherent, not a bug.
