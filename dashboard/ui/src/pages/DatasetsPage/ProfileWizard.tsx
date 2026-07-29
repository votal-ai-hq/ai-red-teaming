import { useState } from "react";
import {
  importProfile,
  saveProfile,
  type AppProfile,
  type ProfileTool,
  type Policy,
  type ImportFormat,
} from "@/api/datasets";
import { discoverMcp } from "@/api/reference";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertTriangle,
  Loader2,
  Upload,
  Wand2,
  ArrowRight,
  ArrowLeft,
  Plus,
  Trash2,
  Plug,
} from "lucide-react";

const IMPORT_FORMATS: { id: ImportFormat; label: string; hint: string; placeholder: string }[] = [
  {
    id: "system-prompt",
    label: "System prompt",
    hint: "Paste your app's system prompt / instructions. Business rules are extracted automatically.",
    placeholder: "You are a support assistant. Never reveal internal pricing. Always verify identity before a refund…",
  },
  {
    id: "mcp-manifest",
    label: "MCP tool manifest",
    hint: "Paste a tools/list JSON result from your MCP server.",
    placeholder: '{ "tools": [ { "name": "search_docs", "description": "…" } ] }',
  },
  {
    id: "openapi",
    label: "OpenAPI spec",
    hint: "Paste an OpenAPI/Swagger JSON document. Mutating operations are flagged sensitive.",
    placeholder: '{ "openapi": "3.0.0", "paths": { "/orders": { "post": { … } } } }',
  },
  {
    id: "policy-doc",
    label: "Policy document",
    hint: "Paste or upload your policies (markdown, text, or JSON). Each heading / rule becomes a named policy with criteria that generation targets and grading checks.",
    placeholder:
      "## No cross-tenant access\nThe agent must never read or return another tenant's data.\n\n## Refund limit\nRefunds must never exceed $500 without a manager approval.",
  },
];

const UPLOAD_ACCEPT = ".md,.markdown,.txt,.json,.mdx,text/plain,text/markdown,application/json";

type Step = "import" | "review";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Called after a profile is saved so the parent can select it. */
  onSaved: (profileName: string) => void;
}

const emptyProfile: AppProfile = { name: "" };

export function ProfileWizard({ open, onOpenChange, onSaved }: Props) {
  const [step, setStep] = useState<Step>("import");
  const [source, setSource] = useState<"paste" | "mcp">("paste");
  const [format, setFormat] = useState<ImportFormat>("system-prompt");
  const [content, setContent] = useState("");
  const [profile, setProfile] = useState<AppProfile>(emptyProfile);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Live MCP auto-detect connection fields.
  const [mcpTransport, setMcpTransport] = useState<
    "streamable_http" | "sse" | "stdio"
  >("streamable_http");
  const [mcpUrl, setMcpUrl] = useState("");
  const [mcpCommand, setMcpCommand] = useState("");
  const [mcpArgs, setMcpArgs] = useState("");
  // How to authenticate to the MCP server. Servers differ: some want
  // `Authorization: Bearer`, others a named API-key header (x-api-key), others
  // an arbitrary set of headers.
  const [mcpAuthMode, setMcpAuthMode] = useState<
    "none" | "bearer" | "apikey" | "custom"
  >("none");
  const [mcpBearer, setMcpBearer] = useState("");
  const [mcpApiKeyHeader, setMcpApiKeyHeader] = useState("x-api-key");
  const [mcpApiKeyValue, setMcpApiKeyValue] = useState("");
  const [mcpHeaders, setMcpHeaders] = useState<{ key: string; value: string }[]>([
    { key: "", value: "" },
  ]);

  const reset = () => {
    setStep("import");
    setSource("paste");
    setFormat("system-prompt");
    setContent("");
    setProfile(emptyProfile);
    setError(null);
    setBusy(false);
    setMcpTransport("streamable_http");
    setMcpUrl("");
    setMcpCommand("");
    setMcpArgs("");
    setMcpAuthMode("none");
    setMcpBearer("");
    setMcpApiKeyHeader("x-api-key");
    setMcpApiKeyValue("");
    setMcpHeaders([{ key: "", value: "" }]);
  };

  const close = (o: boolean) => {
    if (!o) reset();
    onOpenChange(o);
  };

  const activeFormat = IMPORT_FORMATS.find((f) => f.id === format)!;

  const runImport = async () => {
    setBusy(true);
    setError(null);
    try {
      const { profile: draft } = await importProfile(format, content);
      setProfile({ ...emptyProfile, ...draft, name: profile.name || "" });
      setStep("review");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  // Connect to a live MCP server, auto-detect its tools, and seed a draft
  // profile from them. The profile then tailors dataset generation to those
  // exact tools (samplers + prompt context).
  const detectMcp = async () => {
    setBusy(true);
    setError(null);
    try {
      const mcp: Record<string, unknown> = { transport: mcpTransport };
      if (mcpTransport === "stdio") {
        if (!mcpCommand.trim()) {
          setError("Enter the command to launch your stdio MCP server.");
          return;
        }
        mcp.command = mcpCommand.trim();
        mcp.args = mcpArgs.trim() ? mcpArgs.trim().split(/\s+/) : [];
      } else {
        if (!mcpUrl.trim()) {
          setError("Enter your MCP server URL.");
          return;
        }
        mcp.url = mcpUrl.trim();
        const headers: Record<string, string> = {};
        if (mcpAuthMode === "bearer" && mcpBearer.trim()) {
          headers["Authorization"] = `Bearer ${mcpBearer.trim()}`;
        } else if (mcpAuthMode === "apikey" && mcpApiKeyValue.trim()) {
          headers[mcpApiKeyHeader.trim() || "x-api-key"] = mcpApiKeyValue.trim();
        } else if (mcpAuthMode === "custom") {
          for (const h of mcpHeaders) {
            if (h.key.trim() && h.value.trim()) headers[h.key.trim()] = h.value.trim();
          }
        }
        if (Object.keys(headers).length > 0) mcp.headers = headers;
      }
      const config = {
        target: { type: "mcp", baseUrl: "", agentEndpoint: "", mcp },
        auth: { methods: ["none"], credentials: [], apiKeys: {} },
        requestSchema: { messageField: "message", roleField: "role" },
        responseSchema: { responsePath: "", toolCallsPath: "" },
        attackConfig: {},
      };
      const result = await discoverMcp(config);
      if (!result.ok) {
        setError(result.error || "Could not connect to the MCP server.");
        return;
      }
      const tools: ProfileTool[] = (result.tools ?? []).map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      }));
      if (tools.length === 0) {
        setError("Connected, but the server exposed no tools.");
        return;
      }
      const suggestedName = (result.serverInfo?.name || "")
        .toLowerCase()
        .replace(/[^a-z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "");
      setProfile({
        ...emptyProfile,
        name: suggestedName,
        description: result.serverInfo?.name
          ? `MCP server: ${result.serverInfo.name}`
          : "",
        tools,
        source: "mcp-discover",
      });
      setStep("review");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const skipToManual = () => {
    setProfile({ ...emptyProfile, source: "manual" });
    setStep("review");
    setError(null);
  };

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await saveProfile(profile);
      onSaved(profile.name);
      close(false);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const setField = <K extends keyof AppProfile>(k: K, v: AppProfile[K]) =>
    setProfile((p) => ({ ...p, [k]: v }));

  const linesToList = (s: string) =>
    s.split("\n").map((x) => x.trim()).filter(Boolean);
  const listToLines = (a?: string[]) => (a ?? []).join("\n");

  const setPolicy = (i: number, patch: Partial<Policy>) =>
    setProfile((p) => {
      const policies = [...(p.policies ?? [])];
      policies[i] = { ...policies[i], ...patch };
      return { ...p, policies };
    });
  const addPolicy = () =>
    setProfile((p) => ({
      ...p,
      policies: [...(p.policies ?? []), { name: "", criteria: "" }],
    }));
  const removePolicy = (i: number) =>
    setProfile((p) => ({
      ...p,
      policies: (p.policies ?? []).filter((_, j) => j !== i),
    }));

  const toggleSensitive = (i: number) =>
    setProfile((p) => {
      const tools = [...(p.tools ?? [])];
      tools[i] = { ...tools[i], sensitive: !tools[i].sensitive };
      return { ...p, tools };
    });

  const nameValid = /^[a-z0-9][a-z0-9._-]*$/i.test(profile.name.trim());

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Wand2 className="w-4 h-4 text-primary" />
            Customize for my app
          </DialogTitle>
          <DialogDescription>
            {step === "import"
              ? "Connect to a live MCP server to auto-detect its tools, paste an artifact you already have, or skip to enter details by hand. This tailors generated datasets to your app's domain, rules, and tools."
              : "Review and edit what we found, then save this profile to reuse across datasets."}
          </DialogDescription>
        </DialogHeader>

        {step === "import" && (
          <div className="space-y-4">
            <div className="flex gap-1">
              <Button
                size="sm"
                variant={source === "paste" ? "default" : "outline"}
                onClick={() => {
                  setSource("paste");
                  setError(null);
                }}
              >
                Paste an artifact
              </Button>
              <Button
                size="sm"
                variant={source === "mcp" ? "default" : "outline"}
                onClick={() => {
                  setSource("mcp");
                  setError(null);
                }}
              >
                <Plug className="w-3.5 h-3.5" />
                Connect MCP server
              </Button>
            </div>

            {source === "mcp" && (
              <div className="space-y-3 rounded-lg border border-dashed border-border p-3">
                <p className="text-[11px] text-muted-foreground">
                  Connect to a live MCP server and we'll auto-detect its tools,
                  then tailor the generated dataset to exactly those tools.
                </p>
                <div className="space-y-1">
                  <Label className="text-xs">Transport</Label>
                  <div className="flex flex-wrap gap-1">
                    {(["streamable_http", "sse", "stdio"] as const).map((t) => (
                      <Button
                        key={t}
                        size="sm"
                        variant={mcpTransport === t ? "default" : "outline"}
                        onClick={() => setMcpTransport(t)}
                      >
                        {t}
                      </Button>
                    ))}
                  </div>
                </div>
                {mcpTransport === "stdio" ? (
                  <div className="grid gap-2 sm:grid-cols-2">
                    <div className="space-y-1">
                      <Label className="text-xs" htmlFor="mcp-cmd">
                        Command
                      </Label>
                      <Input
                        id="mcp-cmd"
                        className="text-xs"
                        value={mcpCommand}
                        onChange={(e) => setMcpCommand(e.target.value)}
                        placeholder="node"
                      />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs" htmlFor="mcp-args">
                        Args (space-separated)
                      </Label>
                      <Input
                        id="mcp-args"
                        className="text-xs"
                        value={mcpArgs}
                        onChange={(e) => setMcpArgs(e.target.value)}
                        placeholder="./server.js --flag"
                      />
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="space-y-1">
                      <Label className="text-xs" htmlFor="mcp-url">
                        Server URL
                      </Label>
                      <Input
                        id="mcp-url"
                        className="text-xs"
                        value={mcpUrl}
                        onChange={(e) => setMcpUrl(e.target.value)}
                        placeholder="https://your-mcp-server.example.com/api/mcp"
                      />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs">Authentication</Label>
                      <div className="flex flex-wrap gap-1">
                        {(
                          [
                            ["none", "None"],
                            ["bearer", "Bearer token"],
                            ["apikey", "API key header"],
                            ["custom", "Custom headers"],
                          ] as const
                        ).map(([id, label]) => (
                          <Button
                            key={id}
                            size="sm"
                            variant={mcpAuthMode === id ? "default" : "outline"}
                            onClick={() => setMcpAuthMode(id)}
                          >
                            {label}
                          </Button>
                        ))}
                      </div>
                    </div>

                    {mcpAuthMode === "bearer" && (
                      <div className="space-y-1">
                        <Label className="text-xs" htmlFor="mcp-bearer">
                          Token
                        </Label>
                        <Input
                          id="mcp-bearer"
                          type="password"
                          className="text-xs"
                          value={mcpBearer}
                          onChange={(e) => setMcpBearer(e.target.value)}
                          placeholder="sent as Authorization: Bearer …"
                        />
                      </div>
                    )}

                    {mcpAuthMode === "apikey" && (
                      <div className="grid gap-2 sm:grid-cols-2">
                        <div className="space-y-1">
                          <Label className="text-xs" htmlFor="mcp-keyname">
                            Header name
                          </Label>
                          <Input
                            id="mcp-keyname"
                            className="text-xs font-mono"
                            value={mcpApiKeyHeader}
                            onChange={(e) => setMcpApiKeyHeader(e.target.value)}
                            placeholder="x-api-key"
                          />
                        </div>
                        <div className="space-y-1">
                          <Label className="text-xs" htmlFor="mcp-keyval">
                            Key
                          </Label>
                          <Input
                            id="mcp-keyval"
                            type="password"
                            className="text-xs"
                            value={mcpApiKeyValue}
                            onChange={(e) => setMcpApiKeyValue(e.target.value)}
                            placeholder="your API key"
                          />
                        </div>
                      </div>
                    )}

                    {mcpAuthMode === "custom" && (
                      <div className="space-y-1">
                        <Label className="text-xs">Headers</Label>
                        {mcpHeaders.map((h, i) => (
                          <div key={i} className="flex items-center gap-1.5">
                            <Input
                              className="text-xs font-mono flex-1"
                              value={h.key}
                              onChange={(e) =>
                                setMcpHeaders((hs) =>
                                  hs.map((x, j) =>
                                    j === i ? { ...x, key: e.target.value } : x,
                                  ),
                                )
                              }
                              placeholder="header-name"
                            />
                            <Input
                              type="password"
                              className="text-xs flex-1"
                              value={h.value}
                              onChange={(e) =>
                                setMcpHeaders((hs) =>
                                  hs.map((x, j) =>
                                    j === i ? { ...x, value: e.target.value } : x,
                                  ),
                                )
                              }
                              placeholder="value"
                            />
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() =>
                                setMcpHeaders((hs) =>
                                  hs.length > 1 ? hs.filter((_, j) => j !== i) : hs,
                                )
                              }
                              title="Remove header"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </Button>
                          </div>
                        ))}
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            setMcpHeaders((hs) => [...hs, { key: "", value: "" }])
                          }
                        >
                          <Plus className="w-3.5 h-3.5" />
                          Add header
                        </Button>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {source === "paste" && (
            <div className="space-y-1">
              <Label className="text-xs">Import from</Label>
              <div className="flex flex-wrap gap-1">
                {IMPORT_FORMATS.map((f) => (
                  <Button
                    key={f.id}
                    size="sm"
                    variant={format === f.id ? "default" : "outline"}
                    onClick={() => setFormat(f.id)}
                  >
                    {f.label}
                  </Button>
                ))}
              </div>
              <p className="text-[11px] text-muted-foreground">{activeFormat.hint}</p>
            </div>
            )}
            {source === "paste" && (
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-muted-foreground">
                Paste below, or
              </span>
              <label className="inline-flex items-center gap-1.5 text-xs text-primary cursor-pointer hover:underline">
                <Upload className="w-3.5 h-3.5" />
                Upload a file
                <input
                  type="file"
                  className="hidden"
                  accept={UPLOAD_ACCEPT}
                  onChange={async (e) => {
                    const file = e.target.files?.[0];
                    if (!file) return;
                    setError(null);
                    try {
                      setContent(await file.text());
                    } catch {
                      setError("Could not read that file.");
                    }
                    e.target.value = "";
                  }}
                />
              </label>
            </div>
            )}
            {source === "paste" && (
            <Textarea
              className="min-h-48 font-mono text-xs"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={activeFormat.placeholder}
            />
            )}
            {error && (
              <Alert variant="destructive">
                <AlertTriangle className="w-4 h-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </div>
        )}

        {step === "review" && (
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1">
                <Label className="text-xs" htmlFor="p-name">
                  Profile name <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="p-name"
                  value={profile.name}
                  onChange={(e) => setField("name", e.target.value)}
                  placeholder="my-app"
                  aria-invalid={profile.name.length > 0 && !nameValid}
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs" htmlFor="p-desc">
                  What the app does
                </Label>
                <Input
                  id="p-desc"
                  value={profile.description ?? ""}
                  onChange={(e) => setField("description", e.target.value)}
                  placeholder="a retail banking assistant"
                />
              </div>
            </div>

            <div className="space-y-1">
              <Label className="text-xs" htmlFor="p-sys">
                System prompt / guardrails
              </Label>
              <Textarea
                id="p-sys"
                className="min-h-20 text-xs"
                value={profile.systemPrompt ?? ""}
                onChange={(e) => setField("systemPrompt", e.target.value)}
                placeholder="The instructions your app runs with (attacks try to subvert these)."
              />
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <Label className="text-xs">
                  Policies ({profile.policies?.length ?? 0}) — a name + the
                  criteria a successful attack violates
                </Label>
                <Button size="sm" variant="outline" onClick={addPolicy}>
                  <Plus className="w-3.5 h-3.5" />
                  Add policy
                </Button>
              </div>
              {(profile.policies ?? []).length === 0 && (
                <p className="text-[11px] text-muted-foreground">
                  No policies yet. Import a policy document above, or add them
                  here — each becomes a targeted generation instruction and a
                  precise grading criterion.
                </p>
              )}
              {(profile.policies ?? []).map((pol: Policy, i) => (
                <div
                  key={i}
                  className="flex items-start gap-1.5 rounded-lg border border-border p-2"
                >
                  <div className="flex-1 space-y-1">
                    <Input
                      className="text-xs font-medium"
                      value={pol.name}
                      onChange={(e) => setPolicy(i, { name: e.target.value })}
                      placeholder="Policy name (e.g. No cross-tenant access)"
                    />
                    <Textarea
                      className="min-h-12 text-xs"
                      value={pol.criteria}
                      onChange={(e) => setPolicy(i, { criteria: e.target.value })}
                      placeholder="Criteria — the checkable rule (e.g. The agent must never return another tenant's data)."
                    />
                  </div>
                  <Button
                    size="icon-sm"
                    variant="ghost"
                    onClick={() => removePolicy(i)}
                    title="Remove policy"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                </div>
              ))}
            </div>

            <div className="space-y-1">
              <Label className="text-xs" htmlFor="p-rules">
                Business rules — one per line
              </Label>
              <Textarea
                id="p-rules"
                className="min-h-20 text-xs"
                value={listToLines(profile.businessRules)}
                onChange={(e) => setField("businessRules", linesToList(e.target.value))}
                placeholder={"Never issue a refund over $500\nNever expose another tenant's data"}
              />
              <p className="text-[11px] text-muted-foreground">
                Invariants your app must never violate — they become grading criteria.
              </p>
            </div>

            <div className="space-y-1">
              <Label className="text-xs">
                Tools ({profile.tools?.length ?? 0}) — click a chip to mark it
                sensitive (high-value target)
              </Label>
              <div className="flex flex-wrap gap-1.5 rounded-lg border border-border p-2 min-h-10">
                {(profile.tools ?? []).length === 0 && (
                  <span className="text-[11px] text-muted-foreground">
                    No tools. Add them below or import a manifest/OpenAPI spec.
                  </span>
                )}
                {(profile.tools ?? []).map((t: ProfileTool, i) => (
                  <button
                    key={t.name + i}
                    type="button"
                    onClick={() => toggleSensitive(i)}
                    title={t.description || t.name}
                  >
                    <Badge
                      variant={t.sensitive ? "default" : "secondary"}
                      className="cursor-pointer"
                    >
                      {t.sensitive ? "🔒 " : ""}
                      {t.name}
                    </Badge>
                  </button>
                ))}
              </div>
              <Input
                className="text-xs"
                placeholder="Add tools, comma-separated, then press Enter"
                onKeyDown={(e) => {
                  if (e.key !== "Enter") return;
                  e.preventDefault();
                  const val = (e.target as HTMLInputElement).value;
                  const names = val.split(",").map((x) => x.trim()).filter(Boolean);
                  if (!names.length) return;
                  setProfile((p) => {
                    const existing = new Set(
                      (p.tools ?? []).map((t) => t.name.toLowerCase()),
                    );
                    const added = names
                      .filter((n) => !existing.has(n.toLowerCase()))
                      .map((name) => ({ name }));
                    return { ...p, tools: [...(p.tools ?? []), ...added] };
                  });
                  (e.target as HTMLInputElement).value = "";
                }}
              />
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1">
                <Label className="text-xs" htmlFor="p-roles">
                  Roles — one per line
                </Label>
                <Textarea
                  id="p-roles"
                  className="min-h-16 text-xs"
                  value={listToLines(profile.roles)}
                  onChange={(e) => setField("roles", linesToList(e.target.value))}
                  placeholder={"customer\nadmin"}
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs" htmlFor="p-data">
                  Sensitive data — one per line
                </Label>
                <Textarea
                  id="p-data"
                  className="min-h-16 text-xs"
                  value={listToLines(profile.dataClasses)}
                  onChange={(e) => setField("dataClasses", linesToList(e.target.value))}
                  placeholder={"PII\naccount numbers"}
                />
              </div>
            </div>

            {error && (
              <Alert variant="destructive">
                <AlertTriangle className="w-4 h-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </div>
        )}

        <DialogFooter className="sm:justify-between">
          {step === "import" ? (
            <>
              <Button variant="ghost" onClick={skipToManual} disabled={busy}>
                Skip — enter by hand
              </Button>
              {source === "mcp" ? (
                <Button onClick={detectMcp} disabled={busy}>
                  {busy ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Plug className="w-4 h-4" />
                  )}
                  {busy ? "Connecting…" : "Connect & detect tools"}
                  <ArrowRight className="w-4 h-4" />
                </Button>
              ) : (
                <Button onClick={runImport} disabled={busy || !content.trim()}>
                  {busy ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Upload className="w-4 h-4" />
                  )}
                  Import
                  <ArrowRight className="w-4 h-4" />
                </Button>
              )}
            </>
          ) : (
            <>
              <Button variant="ghost" onClick={() => setStep("import")} disabled={busy}>
                <ArrowLeft className="w-4 h-4" />
                Back
              </Button>
              <Button onClick={save} disabled={busy || !nameValid}>
                {busy ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Wand2 className="w-4 h-4" />
                )}
                Save profile &amp; use
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default ProfileWizard;
