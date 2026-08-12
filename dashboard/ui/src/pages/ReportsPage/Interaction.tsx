import { useState, type ReactNode } from "react";
import { ChevronDown, ChevronRight, Braces, ArrowRight } from "lucide-react";
import {
  buildProtocolTrace,
  partyLabel,
  requestTitle,
  type FlowParty,
  type FlowStep,
  type KeyValue,
  type RequestSummary,
  type ResponseSummary,
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

const PARTY_STYLE: Record<FlowParty, string> = {
  user: "bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300",
  model: "bg-violet-100 text-violet-700 dark:bg-violet-950 dark:text-violet-300",
  server: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200",
  system: "bg-muted text-muted-foreground",
};

function PartyChip({ party, isMcp }: { party: FlowParty; isMcp: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-semibold ${PARTY_STYLE[party]}`}
    >
      {partyLabel(party, isMcp)}
    </span>
  );
}

function FlowRow({ step, isMcp }: { step: FlowStep; isMcp: boolean }) {
  const [open, setOpen] = useState(step.tone !== "note");
  const accent =
    step.tone === "error"
      ? "border-l-red-400"
      : step.tone === "request"
        ? "border-l-blue-400"
        : step.tone === "model"
          ? "border-l-violet-400"
          : step.tone === "response"
            ? "border-l-emerald-400"
            : "border-l-border";

  return (
    <li className={`rounded-r-lg border border-l-2 border-border ${accent} bg-card`}>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        className="w-full flex items-start gap-2 px-2.5 py-2 text-left"
      >
        {open ? (
          <ChevronDown size={13} className="mt-1 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight size={13} className="mt-1 shrink-0 text-muted-foreground" />
        )}
        <span className="text-[11px] font-mono text-muted-foreground mt-0.5 shrink-0">
          {step.index}
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-1.5">
            <PartyChip party={step.from} isMcp={isMcp} />
            <ArrowRight className="w-3 h-3 text-muted-foreground shrink-0" />
            <PartyChip party={step.to} isMcp={isMcp} />
            <span className="text-[12px] font-medium text-foreground break-words">
              {step.title}
            </span>
            {step.turn != null && (
              <span className="text-[10px] text-muted-foreground">
                turn {step.turn}
              </span>
            )}
            {step.statusCode != null && (
              <span className="text-[10px] text-muted-foreground">
                HTTP {step.statusCode}
              </span>
            )}
            {step.timeMs != null && (
              <span className="text-[10px] text-muted-foreground">
                {step.timeMs}ms
              </span>
            )}
            {step.tags.map((t) => (
              <Tag key={t} text={t} />
            ))}
          </span>
        </span>
      </button>

      {open && (
        <div className="px-2.5 pb-2.5 pl-8 space-y-2">
          {step.request && <RequestBody request={step.request} />}
          {step.response && <ResponseBody response={step.response} />}
          {step.note && <ExpandableText text={truncateForNote(step.note)} maxLines={6} />}
        </div>
      )}
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
  if (steps.length === 0) return null;
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">
        Interaction Flow ({steps.length} step{steps.length === 1 ? "" : "s"})
      </div>
      <ol className="space-y-1.5">
        {steps.map((step) => (
          <FlowRow key={step.index} step={step} isMcp={isMcp} />
        ))}
      </ol>
    </div>
  );
}

/* ─── JSON-RPC protocol trace ─── */

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
        <div className="mt-2 space-y-1.5">
          <ol className="space-y-1">
            {events.map((event) => (
              <li
                key={event.index}
                className="rounded-md border border-border/70 px-2 py-1.5"
              >
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[10px] font-mono text-muted-foreground">
                    {event.index}
                  </span>
                  <span
                    className={`text-[10px] font-semibold ${
                      event.from === "user"
                        ? "text-blue-600 dark:text-blue-400"
                        : "text-slate-600 dark:text-slate-300"
                    }`}
                  >
                    {event.from === "user" ? "client → server" : "server → client"}
                  </span>
                  <span className="text-[11px] font-medium text-foreground break-all">
                    {event.label}
                  </span>
                  {event.isError && (
                    <span className="text-[10px] font-semibold text-red-600 dark:text-red-400">
                      error
                    </span>
                  )}
                </div>
                {event.summary && (
                  <p className="mt-0.5 text-[11px] text-muted-foreground whitespace-pre-wrap break-words">
                    {event.summary}
                  </p>
                )}
                <RawJsonToggle data={event.raw} label="raw message" />
              </li>
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
