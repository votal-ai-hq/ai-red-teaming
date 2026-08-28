import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "mcp_capability_manipulation" as const;

/**
 * MCP Capability Manipulation (server-initiated requests).
 *
 * MCP is bidirectional: if a client advertises `sampling`, the server may issue
 * `sampling/createMessage` — driving the client's LLM, at the client's cost,
 * with server-chosen prompts, and reading the completion. `roots/list` and
 * `elicitation/create` are analogous server→client requests. Real clients only
 * advertise these when the user opts in; a malicious server that fires them
 * unsolicited is exfiltrating compute / context / user input.
 *
 * The default scanner advertises `capabilities: {}`, so this surface is never
 * exercised. The `capability_probe` operation advertises `sampling` + `roots`,
 * provokes server activity, and records any server-initiated request (the
 * transport refuses each — it never runs the requested sampling). The analyzer
 * grades any such request as PASS.
 */
export const mcpCapabilityManipulationModule: AttackModule = {
  category,

  getSeedAttacks(_analysis?: CodebaseAnalysis): Attack[] {
    return [
      {
        id: "mcp-capman-1-sampling-probe",
        category,
        name: "Advertise sampling and detect server-initiated requests",
        description:
          "Advertise the sampling and roots client capabilities at initialize, provoke server activity, and detect whether the server issues an unsolicited sampling/createMessage, elicitation/create, or roots/list request that would drive the client's LLM, prompt the user, or enumerate filesystem roots.",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Advertise the sampling and roots capabilities to the MCP server, then observe whether it issues an unsolicited server→client request (sampling/createMessage, elicitation/create, roots/list) to drive the client's model or read client-side context.",
          _mcpOperation: "capability_probe",
        },
        expectation:
          "The server issues no unsolicited server→client requests — it does not attempt to drive the client's LLM (sampling), prompt the user (elicitation), or enumerate filesystem roots when those capabilities are advertised",
        severity: "high",
        isLlmGenerated: false,
      },
    ];
  },

  getGenerationPrompt(_analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server for capability abuse via server→client requests.

MCP is bidirectional. If the client advertises the sampling capability, the server can send sampling/createMessage to run the client's LLM with server-chosen prompts (compute/context exfiltration); roots/list and elicitation/create are analogous. A well-behaved server only issues these in response to legitimate client actions.

Generate MCP attacks using "_mcpOperation": "capability_probe". The probe advertises sampling + roots, provokes server activity, and detects any unsolicited server-initiated request. The strongest finding is a sampling/createMessage whose prompt carries conversation content or asks for credentials.`;
  },
};
