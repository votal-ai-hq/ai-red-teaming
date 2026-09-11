import {
  useEffect,
  useRef,
  useState,
  type MouseEvent,
  type ReactNode,
} from "react";
import { ChevronDown, ChevronRight, Braces, Check, Copy } from "lucide-react";
import {
  buildProtocolTrace,
  partyLabel,
  requestTitle,
  type FlowStep,
  type KeyValue,
  type ProtocolEvent,
  type RequestSummary,
  type ResponseSummary,
  type StructuredTable,
  type TraceLike,
} from "@/lib/mcp-report";

/**
 * Report rendering for a single attack's traffic.
 *
 * MCP requests and responses used to be dumped as raw JSON. These components
 * render the same data as labelled fields and plain text, with the raw JSON kept
 * one click away for advanced users, plus an ordered User → Model → MCP server
 * flow so the whole conversation is traceable.
 */

/* ─── primitives ─── */

/** Long text with a show-more toggle. */
export function ExpandableText({
  text,
  maxLines = 4,
}: {
  text: string;
  maxLines?: number;
}) {
  const [showAll, setShowAll] = useState(false);
  const isLong = text.length > maxLines * 100;

  return (
    <div>
      <p
        className="text-[13px] text-foreground whitespace-pre-wrap break-words"
        style={
          !showAll && isLong
            ? {
                WebkitLineClamp: maxLines,
                display: "-webkit-box",
                WebkitBoxOrient: "vertical",
                overflow: "hidden",
              }
            : undefined
        }
      >
        {text}
      </p>
      {isLong && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            setShowAll(!showAll);
          }}
          className="text-[11px] font-medium text-primary hover:underline mt-1"
        >
          {showAll ? "Show less" : "Show more"}
        </button>
      )}
    </div>
  );
}

/** Collapsed raw-JSON escape hatch — the advanced view QA asked to keep. */
export function RawJsonToggle({
  data,
  label = "Raw JSON",
}: {
  data: unknown;
  label?: string;
}) {
  const [open, setOpen] = useState(false);
  if (data == null) return null;
  const text =
    typeof data === "string"
      ? data
      : (() => {
          try {
            return JSON.stringify(data, null, 2);
          } catch {
            return String(data);
          }
        })();

  return (
    <div className="mt-2">
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        className="inline-flex items-center gap-1 text-[11px] font-medium text-muted-foreground hover:text-foreground"
      >
        <Braces className="w-3 h-3" />
        {open ? "Hide" : "Show"} {label}
      </button>
      {open && (
        <pre className="mt-1.5 max-h-72 overflow-auto rounded-md border border-border bg-muted/40 p-2 text-[11px] leading-relaxed text-foreground whitespace-pre">
          {text}
        </pre>
      )}
    </div>
  );
}

/** Label/value rows. Long values wrap instead of stretching the grid. */
function Fields({ items, dense = false }: { items: KeyValue[]; dense?: boolean }) {
  if (items.length === 0) return null;
  return (
    <dl className={`grid grid-cols-[minmax(70px,auto)_1fr] gap-x-3 ${dense ? "gap-y-0.5" : "gap-y-1"}`}>
      {items.map((item, i) => (
        <div key={`${item.label}-${i}`} className="col-span-2 grid grid-cols-subgrid">
          <dt className="text-[11px] font-mono text-muted-foreground break-words">
            {item.label}
          </dt>
          <dd className="text-[12px] text-foreground whitespace-pre-wrap break-words min-w-0">
            {item.value === "" ? (
              <span className="italic text-muted-foreground">(empty)</span>
            ) : (
              item.value
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function SectionLabel({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`text-[10px] font-semibold uppercase tracking-wider mb-1.5 flex items-center gap-1.5 flex-wrap ${className}`}
    >
      {children}
    </div>
  );
}

function Tag({ text }: { text: string }) {
  return (
    <span className="inline-flex items-center rounded-md border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-300">
      {text}
    </span>
  );
}

const HIGHLIGHT_COLS = /^(critical|high|medium|low|totalFindings|total_findings|vulnerabilities|vulns|passed|failed|score)$/i;

function ResultTable({ table }: { table: StructuredTable }) {
  if (table.columns.length === 0 || table.rows.length === 0) return null;
  const cols = table.columns.slice(0, 8);
  return (
    <div className="overflow-x-auto rounded-md border border-border">
      {table.title && (
        <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground bg-muted/40 border-b border-border">
          {table.title}
        </div>
      )}
      <table className="w-full text-left text-[11px]">
        <thead>
          <tr className="border-b border-border bg-muted/30">
            {cols.map((col) => (
              <th
                key={col}
                className="px-2 py-1.5 font-semibold text-muted-foreground whitespace-nowrap"
              >
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {table.rows.slice(0, 20).map((row, i) => (
            <tr key={i} className="border-b border-border last:border-0">
              {cols.map((col) => (
                <td
                  key={col}
                  className={`px-2 py-1.5 align-top whitespace-pre-wrap break-words max-w-[220px] ${
                    HIGHLIGHT_COLS.test(col)
                      ? "font-semibold text-foreground"
                      : "text-foreground"
                  }`}
                >
                  {row[col] || "—"}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {table.rows.length > 20 && (
        <p className="px-2 py-1 text-[10px] italic text-muted-foreground">
          Showing 20 of {table.rows.length} rows. Open raw JSON for the rest.
        </p>
      )}
    </div>
  );
}

function truncateForNote(text: string): string {
  return text.length > 4000 ? `${text.slice(0, 4000)}…` : text;
}

/* ─── request / response bodies ─── */

/** The structured body of a request — shared by the panel and the flow. */
export function RequestBody({ request }: { request: RequestSummary }) {
  const head: KeyValue[] = [];
  if (request.operation) head.push({ label: "operation", value: request.operation });
  if (request.tool) head.push({ label: "tool", value: request.tool });
  if (request.resourceUri) head.push({ label: "resource", value: request.resourceUri });
  if (request.promptName) head.push({ label: "prompt", value: request.promptName });
  if (request.authVariant) head.push({ label: "credential", value: request.authVariant });
  if (request.role) head.push({ label: "role", value: request.role });

  const scenario = request.agentScenario;

  return (
    <div className="space-y-2">
      <Fields items={head} />

      {request.args.length > 0 && (
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">
            Arguments
          </div>
          <Fields items={request.args} dense />
          {request.argsRepaired && (
            <p className="mt-1 text-[10px] italic text-muted-foreground">
              Arguments were repaired to satisfy the tool schema before sending.
            </p>
          )}
        </div>
      )}

      {scenario && (
        <div className="space-y-1.5">
          {scenario.userTask && (
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                Task given to the model
              </div>
              <ExpandableText text={scenario.userTask} maxLines={4} />
            </div>
          )}
          <Fields
            items={[
              ...(scenario.poisonedTool
                ? [{ label: "poisoned tool", value: scenario.poisonedTool }]
                : []),
              ...(scenario.canary ? [{ label: "canary", value: scenario.canary }] : []),
              ...(scenario.writeTools?.length
                ? [{ label: "write tools", value: scenario.writeTools.join(", ") }]
                : []),
            ]}
          />
          {scenario.poisonedContent && (
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                Injected content
              </div>
              <ExpandableText text={scenario.poisonedContent} maxLines={4} />
            </div>
          )}
        </div>
      )}

      {request.message && (
        <div>
          {(head.length > 0 || request.args.length > 0) && (
            <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">
              Message
            </div>
          )}
          <ExpandableText text={request.message} maxLines={6} />
        </div>
      )}

      <Fields items={request.extras} />

      {request.isEmpty && (
        <p className="text-xs italic text-muted-foreground">
          No request payload recorded.
        </p>
      )}

      <RawJsonToggle data={request.raw} label="raw request" />
    </div>
  );
}

/** The structured body of a response — shared by the panel and the flow. */
export function ResponseBody({ response }: { response: ResponseSummary }) {
  const loop = response.agentLoop;

  return (
    <div className="space-y-2">
      {response.headline && (
        <p
          className={`text-[12px] font-medium ${
            response.isError
              ? "text-red-600 dark:text-red-400"
              : "text-foreground"
          }`}
        >
          {response.headline}
        </p>
      )}

      {response.text ? (
        <ExpandableText text={response.text} maxLines={6} />
      ) : (
        !loop &&
        response.fields.length === 0 && (
          <p className="text-xs italic text-muted-foreground">
            No text response — the target answered via tool calls or a
            side-channel.
          </p>
        )
      )}

      <Fields items={response.fields} />

      {response.tables?.map((table, i) => (
        <ResultTable key={`${table.title ?? "table"}-${i}`} table={table} />
      ))}

      {loop && (
        <div className="space-y-1.5">
          {loop.toolCalls.length > 0 && (
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                Tools the model invoked
              </div>
              <ul className="space-y-1">
                {loop.toolCalls.map((call, i) => (
                  <li
                    key={`${call.tool}-${i}`}
                    className="text-[12px] text-foreground flex flex-wrap items-center gap-1.5"
                  >
                    <span className="font-mono text-muted-foreground">
                      step {call.step}
                    </span>
                    <span className="font-medium">{call.tool}</span>
                    {call.risk === "write" && <Tag text="write tool" />}
                    {call.afterPoisonedRead && <Tag text="after poisoned read" />}
                    {call.canaryInArgs && <Tag text="canary in arguments" />}
                    {call.taintedArgs.length > 0 && (
                      <Tag text={`tainted: ${call.taintedArgs.join(", ")}`} />
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {response.truncated && (
        <p className="text-[10px] italic text-muted-foreground">
          The stored response was truncated by the report writer.
        </p>
      )}

      <RawJsonToggle data={response.raw} label="raw response" />
    </div>
  );
}

/* ─── side-by-side request / response panels ─── */

export function RequestPanel({ request }: { request: RequestSummary }) {
  return (
    <div className="min-w-0 rounded-lg border border-blue-200 dark:border-blue-900 bg-blue-50/30 dark:bg-blue-950/10 p-3">
      <SectionLabel className="text-blue-600 dark:text-blue-400">
        <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
        Request
        <span className="font-normal normal-case tracking-normal text-muted-foreground">
          {requestTitle(request)}
        </span>
      </SectionLabel>
      <RequestBody request={request} />
    </div>
  );
}

export function ResponsePanel({
  response,
  statusCode,
  timeMs,
}: {
  response: ResponseSummary;
  statusCode?: number;
  timeMs?: number;
}) {
  return (
    <div
      className={`min-w-0 rounded-lg border p-3 ${
        response.isError
          ? "border-red-200 dark:border-red-900 bg-red-50/20 dark:bg-red-950/10"
          : "border-border bg-card"
      }`}
    >
      <SectionLabel
        className={
          response.isError
            ? "text-red-600 dark:text-red-400"
            : "text-muted-foreground"
        }
      >
        <span
          className={`w-1.5 h-1.5 rounded-full ${
            response.isError ? "bg-red-500" : "bg-muted-foreground/50"
          }`}
        />
        Response
        {response.operation && (
          <span className="font-normal normal-case tracking-normal text-muted-foreground">
            {response.operation}
          </span>
        )}
        {statusCode != null && (
          <span className="font-normal normal-case tracking-normal text-muted-foreground">
            HTTP {statusCode}
          </span>
        )}
        {timeMs != null && (
          <span className="font-normal normal-case tracking-normal text-muted-foreground">
            {timeMs}ms
          </span>
        )}
      </SectionLabel>
      <ResponseBody response={response} />
    </div>
  );
}

/* ─── interaction flow ─── */

/**
 * The flow renders as a chat transcript. Steps the user sends are right-aligned
 * bubbles, steps addressed to the user are left-aligned bubbles, and everything
 * in between (system prompts, the model's tool calls, tool results) is a
 * compact divider row that expands on demand. A rail on the left keeps the
 * 1-based step numbers so a step can still be cited by index.
 */

type StepKind = "user" | "agent" | "aside";

function stepKind(step: FlowStep): StepKind {
  if (step.from === "user") return "user";
  if (step.to === "user") return "agent";
  return "aside";
}

/** Titles that only restate what the bubble's position already says. */
const GENERIC_TITLES = new Set(["Request", "Response", "User message", "User task"]);

function firstText(...values: Array<string | undefined>): string | undefined {
  return values.find((v) => typeof v === "string" && v.trim().length > 0);
}

/** Plain-text transcript for the clipboard, one block per step. */
export function transcriptText(steps: FlowStep[], isMcp: boolean): string {
  return steps
    .map((step) => {
      const who = partyLabel(step.from, isMcp);
      const turn = step.turn != null ? ` · turn ${step.turn}` : "";
      const body =
        firstText(
          step.request?.message,
          step.note,
          step.response?.text,
          step.response?.headline,
        ) ?? step.title;
      return `[${step.index}] ${who}${turn}: ${body}`;
    })
    .join("\n\n");
}

function stop(e: MouseEvent) {
  e.stopPropagation();
}

function CopyTranscriptButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const id = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(id);
  }, [copied]);

  return (
    <button
      type="button"
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
        } catch {
          /* clipboard blocked — the transcript is visible to copy manually */
        }
      }}
      className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2 py-1 text-[11px] font-medium text-muted-foreground hover:text-foreground"
    >
      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
      {copied ? "Copied" : "Copy transcript"}
    </button>
  );
}

function StepMeta({ step }: { step: FlowStep }) {
  if (step.statusCode == null && step.timeMs == null) return null;
  return (
    <span className="inline-flex items-center gap-2 text-[10px] text-muted-foreground">
      {step.statusCode != null && <span>HTTP {step.statusCode}</span>}
      {step.timeMs != null && <span>{step.timeMs}ms</span>}
    </span>
  );
}

function StepBody({ step }: { step: FlowStep }) {
  return (
    <div className="space-y-2">
      {step.request && <RequestBody request={step.request} />}
      {step.response && <ResponseBody response={step.response} />}
      {step.note && <ExpandableText text={truncateForNote(step.note)} maxLines={6} />}
      {!step.request && !step.response && step.raw != null && (
        <RawJsonToggle data={step.raw} label="raw step" />
      )}
    </div>
  );
}

/** A user or agent message, laid out like a chat bubble. */
function Bubble({
  step,
  isMcp,
  side,
}: {
  step: FlowStep;
  isMcp: boolean;
  side: "user" | "agent";
}) {
  const isUser = side === "user";
  const isError = step.tone === "error";
  const showTitle = !GENERIC_TITLES.has(step.title);

  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
      <div
        className={`min-w-0 max-w-[85%] rounded-xl border px-3 py-2 ${
          isUser
            ? "border-blue-200 bg-blue-50 dark:border-blue-900 dark:bg-blue-950/40"
            : "border-border bg-card"
        } ${isError ? "rounded-l-none border-l-2 border-l-red-400" : ""}`}
      >
        <div className="mb-1 flex flex-wrap items-center gap-1.5">
          <span
            className={`text-[11px] font-semibold ${
              isUser ? "text-blue-700 dark:text-blue-300" : "text-foreground"
            }`}
          >
            {partyLabel(step.from, isMcp)}
          </span>
          {showTitle && (
            <span className="text-[11px] text-muted-foreground break-words">
              {step.title}
            </span>
          )}
          {step.turn != null && (
            <span className="text-[10px] text-muted-foreground">turn {step.turn}</span>
          )}
          {step.tags.map((t) => (
            <Tag key={t} text={t} />
          ))}
        </div>

        <StepBody step={step} />

        {(step.statusCode != null || step.timeMs != null) && (
          <div className="mt-1.5">
            <StepMeta step={step} />
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * A step that is neither sent by nor addressed to the user: a system prompt, a
 * tool call, a tool result. Rendered as a centred divider that expands into a
 * detail card. Poisoned tool results (tone `error`) start open.
 */
function AsideRow({ step, isMcp }: { step: FlowStep; isMcp: boolean }) {
  const [open, setOpen] = useState(step.tone === "error");
  const hasBody = Boolean(step.request || step.response || step.note);
  const isError = step.tone === "error";
  const Chevron = open ? ChevronDown : ChevronRight;

  return (
    <div>
      <button
        type="button"
        disabled={!hasBody}
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        className="flex w-full items-center gap-2 text-left disabled:cursor-default"
      >
        <span className="h-px flex-1 bg-border" />
        <span className="flex max-w-[85%] flex-wrap items-center justify-center gap-1.5 px-1">
          {hasBody && <Chevron size={12} className="shrink-0 text-muted-foreground" />}
          <span
            className={`text-[11px] font-medium break-words ${
              isError ? "text-red-600 dark:text-red-400" : "text-muted-foreground"
            }`}
          >
            {step.title}
          </span>
          <span className="text-[10px] text-muted-foreground">
            {partyLabel(step.from, isMcp)} → {partyLabel(step.to, isMcp)}
          </span>
          {step.tags.map((t) => (
            <Tag key={t} text={t} />
          ))}
          <StepMeta step={step} />
        </span>
        <span className="h-px flex-1 bg-border" />
      </button>

      {open && hasBody && (
        <div
          className={`mt-2 rounded-lg border px-3 py-2 ${
            isError
              ? "border-red-200 bg-red-50/30 dark:border-red-900 dark:bg-red-950/10"
              : "border-border bg-card"
          }`}
        >
          <StepBody step={step} />
        </div>
      )}
    </div>
  );
}

/** Vertical centre of the step-number chip, so the rail line meets it. */
const RAIL_CHIP_CENTER = "0.875rem";

function RailRow({
  index,
  isFirst,
  isLast,
  rowRef,
  children,
}: {
  index: number;
  isFirst: boolean;
  isLast: boolean;
  rowRef?: (el: HTMLLIElement | null) => void;
  children: ReactNode;
}) {
  const showLine = !(isFirst && isLast);
  return (
    <li
      ref={rowRef}
      className="grid grid-cols-[28px_minmax(0,1fr)] gap-x-2 pb-2 last:pb-0 scroll-mt-4"
    >
      <div className="relative flex justify-center">
        {showLine && (
          <span
            aria-hidden="true"
            className="absolute left-1/2 w-px -translate-x-1/2 bg-border"
            style={{
              top: isFirst ? RAIL_CHIP_CENTER : 0,
              bottom: isLast ? `calc(100% - ${RAIL_CHIP_CENTER})` : 0,
            }}
          />
        )}
        <span className="relative z-[1] mt-1 inline-flex h-5 min-w-5 items-center justify-center rounded-full border border-border bg-card px-1 font-mono text-[10px] text-muted-foreground">
          {index}
        </span>
      </div>
      <div className="min-w-0">{children}</div>
    </li>
  );
}

/** The ordered User → Model → MCP server sequence for one attack. */
export function InteractionFlow({
  steps,
  isMcp,
}: {
  steps: FlowStep[];
  isMcp: boolean;
}) {
  const rowRefs = useRef<Map<number, HTMLLIElement>>(new Map());
  // The whole section can be minimised; it starts open because the transcript
  // is the main evidence for the verdict.
  const [open, setOpen] = useState(true);

  if (steps.length === 0) return null;

  const turns = Array.from(
    new Set(steps.flatMap((s) => (s.turn != null ? [s.turn] : []))),
  ).sort((a, b) => a - b);
  const errorTurns = new Set(
    steps.flatMap((s) => (s.tone === "error" && s.turn != null ? [s.turn] : [])),
  );

  const jumpTo = (turn: number) => {
    const first = steps.find((s) => s.turn === turn);
    const el = first ? rowRefs.current.get(first.index) : undefined;
    el?.scrollIntoView({ block: "start" });
  };

  const summary =
    `${steps.length} step${steps.length === 1 ? "" : "s"}` +
    (turns.length > 0 ? ` · ${turns.length} turn${turns.length === 1 ? "" : "s"}` : "");

  return (
    <div className="rounded-lg border border-border bg-card p-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <button
          type="button"
          aria-expanded={open}
          onClick={(e) => {
            e.stopPropagation();
            setOpen((v) => !v);
          }}
          className="flex min-w-0 flex-1 items-center gap-1.5 text-left"
        >
          {open ? (
            <ChevronDown size={13} className="shrink-0 text-muted-foreground" />
          ) : (
            <ChevronRight size={13} className="shrink-0 text-muted-foreground" />
          )}
          <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            Interaction Flow
          </span>
          <span className="text-[10px] text-muted-foreground">{summary}</span>
        </button>
        {open && <CopyTranscriptButton text={transcriptText(steps, isMcp)} />}
      </div>

      {open && (
        <div className="mt-3">
          {turns.length > 1 && (
            <div
              className="mb-3 flex flex-wrap items-center gap-1"
              onClick={stop}
            >
              <span className="mr-1 text-[10px] text-muted-foreground">Jump to turn</span>
              {turns.map((turn) => (
                <button
                  key={turn}
                  type="button"
                  aria-label={`Jump to turn ${turn}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    jumpTo(turn);
                  }}
                  className={`rounded-md border px-1.5 py-0.5 font-mono text-[10px] ${
                    errorTurns.has(turn)
                      ? "border-red-300 text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950/30"
                      : "border-border text-muted-foreground hover:bg-muted hover:text-foreground"
                  }`}
                >
                  {turn}
                </button>
              ))}
            </div>
          )}

          <ol>
            {steps.map((step, i) => {
              const kind = stepKind(step);
              return (
                <RailRow
                  key={step.index}
                  index={step.index}
                  isFirst={i === 0}
                  isLast={i === steps.length - 1}
                  rowRef={(el) => {
                    if (el) rowRefs.current.set(step.index, el);
                    else rowRefs.current.delete(step.index);
                  }}
                >
                  {kind === "aside" ? (
                    <AsideRow step={step} isMcp={isMcp} />
                  ) : (
                    <Bubble step={step} isMcp={isMcp} side={kind} />
                  )}
                </RailRow>
              );
            })}
          </ol>
        </div>
      )}
    </div>
  );
}

/* ─── JSON-RPC protocol trace ─── */

/** One wire message, laid out like the interaction-flow bubbles. */
function ProtocolBubble({ event }: { event: ProtocolEvent }) {
  const isClient = event.from === "user";
  return (
    <div className={`flex ${isClient ? "justify-end" : "justify-start"}`}>
      <div
        className={`min-w-0 max-w-[85%] rounded-xl border px-3 py-2 ${
          isClient
            ? "border-blue-200 bg-blue-50 dark:border-blue-900 dark:bg-blue-950/40"
            : "border-border bg-card"
        } ${event.isError ? "rounded-l-none border-l-2 border-l-red-400" : ""}`}
      >
        <div className="mb-1 flex flex-wrap items-center gap-1.5">
          <span
            className={`text-[11px] font-semibold ${
              isClient ? "text-blue-700 dark:text-blue-300" : "text-foreground"
            }`}
          >
            {isClient ? "Client" : "Server"}
          </span>
          <span className="text-[11px] text-muted-foreground break-all">
            {event.label}
          </span>
          {event.isNotification && <Tag text="notification" />}
          {event.isError && (
            <span className="text-[10px] font-semibold text-red-600 dark:text-red-400">
              error
            </span>
          )}
        </div>
        {event.summary && <ExpandableText text={event.summary} maxLines={6} />}
        <RawJsonToggle data={event.raw} label="raw message" />
      </div>
    </div>
  );
}

/** The wire-level MCP transcript, collapsed by default. */
export function ProtocolTrace({ trace }: { trace: TraceLike }) {
  const [open, setOpen] = useState(false);
  const events = buildProtocolTrace(trace);
  if (events.length === 0 && !trace.stderr) return null;

  const meta = [trace.transport, trace.serverName, trace.protocolVersion]
    .filter(Boolean)
    .join(" · ");

  return (
    <div className="rounded-lg border border-border bg-card p-3">
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        className="flex w-full items-center gap-1.5 text-left"
      >
        {open ? (
          <ChevronDown size={13} className="shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight size={13} className="shrink-0 text-muted-foreground" />
        )}
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          MCP Protocol Trace ({events.length} message
          {events.length === 1 ? "" : "s"})
        </span>
        {meta && <span className="text-[10px] text-muted-foreground">{meta}</span>}
      </button>

      {open && (
        <div className="mt-3 space-y-1.5">
          <ol>
            {events.map((event, i) => (
              <RailRow
                key={event.index}
                index={event.index}
                isFirst={i === 0}
                isLast={i === events.length - 1}
              >
                <ProtocolBubble event={event} />
              </RailRow>
            ))}
          </ol>
          {trace.stderr && (
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                Server stderr
              </div>
              <pre className="max-h-40 overflow-auto rounded-md border border-border bg-muted/40 p-2 text-[11px] whitespace-pre-wrap">
                {trace.stderr}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
