import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "mcp_session_hijacking" as const;

/**
 * MCP Session Hijacking (streamable_http).
 *
 * The `Mcp-Session-Id` a server assigns at initialize must be cryptographically
 * secure, must NOT be treated as authentication, and requests bearing an
 * unknown/terminated id should get HTTP 404. The `session_probe` operation runs
 * (with credentials stripped): a forged-session-id request, a borrowed
 * real-session request, an unauthenticated DELETE, and a session-id entropy
 * check. The analyzer grades any accepted forged/borrowed session or
 * unauthenticated termination as a hijack (PASS); a low-entropy id is PARTIAL.
 *
 * Network-only — on stdio there is no session id, so the probe reports
 * not-applicable and grades FAIL.
 */
export const mcpSessionHijackingModule: AttackModule = {
  category,

  getSeedAttacks(_analysis?: CodebaseAnalysis): Attack[] {
    return [
      {
        id: "mcp-sesshijack-1-probe",
        category,
        name: "MCP session-id hijack probe",
        description:
          "Capture a legitimate Mcp-Session-Id, then with credentials stripped attempt a forged-session request, a borrowed-session request, and an unauthenticated DELETE, and check the session-id entropy.",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Probe the MCP server's session-id handling: does it accept a forged or borrowed Mcp-Session-Id without credentials, honor an unauthenticated session DELETE, or issue predictable session ids?",
          _mcpOperation: "session_probe",
        },
        expectation:
          "The server rejects forged/borrowed session ids without valid credentials (HTTP 404/401), requires authorization to terminate a session, and issues cryptographically-strong session ids",
        severity: "high",
        isLlmGenerated: false,
      },
    ];
  },

  getGenerationPrompt(_analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server's session handling over streamable HTTP.

Per the MCP spec, the Mcp-Session-Id MUST be cryptographically secure, MUST NOT be used as authentication, and a request with an unknown or terminated session id SHOULD get HTTP 404.

Generate MCP attacks using "_mcpOperation": "session_probe". The probe captures a real session id and, with credentials stripped, tests whether the server accepts a forged session id, honors a borrowed session without the owner's credentials, accepts an unauthenticated DELETE that terminates a session, or issues a predictable/low-entropy session id.`;
  },
};
