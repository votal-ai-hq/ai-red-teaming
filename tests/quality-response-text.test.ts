import { describe, it, expect } from "vitest";
import { toText } from "../lib/dataset/to-text.js";
import {
  extractResponseText,
  parseSseText,
} from "../lib/quality/response-text.js";

describe("toText", () => {
  it("passes strings and scalars through", () => {
    expect(toText("hi")).toBe("hi");
    expect(toText(42)).toBe("42");
    expect(toText(true)).toBe("true");
    expect(toText(null)).toBe("");
    expect(toText(undefined)).toBe("");
  });

  it("never produces [object Object]", () => {
    const out = toText({ severity: "high", cwe: "CWE-89" });
    expect(out).not.toContain("[object Object]");
    expect(JSON.parse(out)).toEqual({ severity: "high", cwe: "CWE-89" });
  });

  it("unwraps MCP-style content blocks", () => {
    expect(
      toText([
        { type: "text", text: "line one" },
        { type: "text", text: "line two" },
      ]),
    ).toBe("line one\nline two");
  });

  it("unwraps { text } and { content } objects", () => {
    expect(toText({ text: "answer" })).toBe("answer");
    expect(toText({ content: "answer" })).toBe("answer");
    expect(toText({ content: [{ text: "a" }, { text: "b" }] })).toBe("a\nb");
  });

  it("joins scalar arrays as lines", () => {
    expect(toText([1, 2, 3])).toBe("1\n2\n3");
    expect(toText(["a", "b"])).toBe("a\nb");
  });

  it("pretty-prints arrays whose entries carry no text", () => {
    const out = toText([{ id: 1 }, { id: 2 }]);
    expect(out).not.toContain("[object Object]");
    expect(JSON.parse(out)).toEqual([{ id: 1 }, { id: 2 }]);
  });
});

describe("parseSseText", () => {
  it("joins OpenAI-style streamed deltas", () => {
    const raw = [
      'data: {"choices":[{"delta":{"content":"Hello"}}]}',
      'data: {"choices":[{"delta":{"content":", world"}}]}',
      "data: [DONE]",
    ].join("\n");
    expect(parseSseText(raw)).toBe("Hello, world");
  });

  it("handles plain data: lines", () => {
    expect(parseSseText("data: alpha\ndata: beta")).toBe("alphabeta");
  });

  it("returns empty for non-SSE text", () => {
    expect(parseSseText("just a normal answer")).toBe("");
  });
});

describe("extractResponseText", () => {
  it("honors the configured responsePath first", () => {
    const body = { answer: "configured", message: "fallback" };
    expect(extractResponseText(body, "answer")).toBe("configured");
  });

  it("falls back to common envelopes when the path misses", () => {
    // responsePath points at a field this target doesn't use.
    expect(extractResponseText({ message: "hi there" }, "answer")).toBe("hi there");
    expect(
      extractResponseText({ choices: [{ message: { content: "gpt style" } }] }),
    ).toBe("gpt style");
    expect(extractResponseText({ data: { content: "nested" } })).toBe("nested");
  });

  it("stringifies a structured response instead of [object Object]", () => {
    const body = { response: { findings: [{ id: 101, severity: "high" }] } };
    const out = extractResponseText(body, "response");
    expect(out).not.toContain("[object Object]");
    expect(out).toContain("101");
  });

  it("returns the whole body when nothing matches, never empty", () => {
    const body = { totally: { unexpected: "shape" } };
    const out = extractResponseText(body, "answer");
    expect(out).not.toBe("");
    expect(out).toContain("unexpected");
  });

  it("parses a streamed body", () => {
    const raw = 'data: {"choices":[{"delta":{"content":"streamed"}}]}\ndata: [DONE]';
    expect(extractResponseText(raw, "answer")).toBe("streamed");
  });

  it("passes a plain string body through", () => {
    expect(extractResponseText("bare text", "answer")).toBe("bare text");
  });
});
