/**
 * Coerce an arbitrary value to text WITHOUT collapsing structure to
 * "[object Object]".
 *
 * Generated references and target responses can be anything — a plain string,
 * an object, an array of content blocks, a provider-specific envelope. Naive
 * `String(v)` turns every object into "[object Object]", which silently
 * destroys the content (and then gets stored in the dataset / scored / shown in
 * the trace). This keeps the information: known text-bearing shapes are
 * unwrapped, and anything else is pretty-printed JSON.
 */
export function toText(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);

  if (Array.isArray(v)) {
    // Content-block arrays: [{type:"text",text:"…"}, …] or plain strings.
    const parts = v.map((el) => {
      if (el == null) return "";
      if (typeof el === "string") return el;
      if (typeof el === "number" || typeof el === "boolean") return String(el);
      if (typeof el === "object") {
        const o = el as Record<string, unknown>;
        if (typeof o.text === "string") return o.text;
        if (typeof o.content === "string") return o.content;
      }
      return "";
    });
    if (parts.some((p) => p.trim())) return parts.filter((p) => p.trim()).join("\n");
    return JSON.stringify(v, null, 2);
  }

  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (typeof o.text === "string") return o.text;
    if (typeof o.content === "string") return o.content;
    if (Array.isArray(o.content)) {
      const inner = toText(o.content);
      if (inner.trim()) return inner;
    }
    return JSON.stringify(v, null, 2);
  }

  return String(v);
}
