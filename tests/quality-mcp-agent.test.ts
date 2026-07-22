import { describe, it, expect } from "vitest";
import {
  runQualityAgent,
  mcpResultToText,
  type QualityAgentDeps,
} from "../lib/quality/mcp-agent.js";
import type { McpToolDescriptor } from "../lib/mcp/types.js";

const TOOLS: McpToolDescriptor[] = [
  { name: "search", description: "search records" },
  { name: "get_order", description: "look up an order" },
];

/** A scripted chat: returns the next canned model reply per call. */
function scriptedChat(replies: string[]) {
  let i = 0;
  return async () => replies[Math.min(i++, replies.length - 1)];
}

describe("mcpResultToText", () => {
  it("joins content[].text blocks", () => {
    expect(
      mcpResultToText({ content: [{ type: "text", text: "hello" }, { type: "text", text: "world" }] }),
    ).toBe("hello\nworld");
  });
  it("passes through strings and JSON-stringifies objects without content", () => {
    expect(mcpResultToText("plain")).toBe("plain");
    expect(mcpResultToText({ ok: true })).toBe('{"ok":true}');
  });
});

describe("runQualityAgent", () => {
  it("records the tool it calls and returns the final answer", async () => {
    const calls: { tool: string; args: unknown }[] = [];
    const deps: QualityAgentDeps = {
      tools: TOOLS,
      chat: scriptedChat([
        JSON.stringify({ action: "call_tool", tool: "get_order", arguments: { id: 91 } }),
        JSON.stringify({ action: "final", answer: "Order 91 shipped yesterday." }),
      ]),
      executeTool: async (tool, args) => {
        calls.push({ tool, args });
        return { content: [{ type: "text", text: "status: shipped" }] };
      },
    };
    const r = await runQualityAgent(deps, "Where is order 91?");
    expect(r.toolCalls).toEqual(["get_order"]);
    expect(r.response).toBe("Order 91 shipped yesterday.");
    expect(calls[0]).toEqual({ tool: "get_order", args: { id: 91 } });
  });

  it("feeds the tool observation back and can chain multiple tools", async () => {
    const deps: QualityAgentDeps = {
      tools: TOOLS,
      chat: scriptedChat([
        JSON.stringify({ action: "call_tool", tool: "search", arguments: { q: "widgets" } }),
        JSON.stringify({ action: "call_tool", tool: "get_order", arguments: { id: 1 } }),
        JSON.stringify({ action: "final", answer: "done" }),
      ]),
      executeTool: async (tool) => `result of ${tool}`,
    };
    const r = await runQualityAgent(deps, "task");
    expect(r.toolCalls).toEqual(["search", "get_order"]);
    expect(r.response).toBe("done");
  });

  it("stops at maxSteps and falls back to the last observation when no final answer", async () => {
    const deps: QualityAgentDeps = {
      tools: TOOLS,
      chat: scriptedChat([
        JSON.stringify({ action: "call_tool", tool: "search", arguments: {} }),
      ]),
      executeTool: async () => "observation-text",
    };
    const r = await runQualityAgent(deps, "task", 2);
    expect(r.steps).toBe(2);
    expect(r.response).toBe("observation-text");
  });

  it("gives up after repeated malformed model output", async () => {
    const deps: QualityAgentDeps = {
      tools: TOOLS,
      chat: scriptedChat(["not json", "still not json", "nope"]),
      executeTool: async () => "x",
    };
    const r = await runQualityAgent(deps, "task", 6);
    expect(r.toolCalls).toEqual([]);
    expect(r.response).toBe("");
  });
});
