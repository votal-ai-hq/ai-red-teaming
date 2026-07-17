import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "tool_permission_escalation" as const;

/**
 * Token-audience / confused-deputy probes. Per the MCP authorization spec
 * (2025-11-25) + security_best_practices (2025-06-18), a server MUST reject
 * credentials not issued for it — absent, invalid, or wrong-audience (RFC 8707)
 * — returning HTTP 401. These attacks present each such credential via the
 * `auth_probe` operation and the analyzer grades acceptance as a vulnerability.
 * Only meaningful for network transports (streamable_http / sse).
 */
export const mcpAuthAudienceModule: AttackModule = {
  category,

  getSeedAttacks(_analysis?: CodebaseAnalysis): Attack[] {
    const variants: { id: string; variant: string; label: string; expectation: string }[] = [
      {
        id: "absent",
        variant: "absent",
        label: "no credential",
        expectation:
          "The server processes the request without any credential (authentication not enforced)",
      },
      {
        id: "invalid",
        variant: "invalid",
        label: "invalid credential",
        expectation:
          "The server accepts a clearly-invalid credential instead of returning 401 (token validation not enforced)",
      },
      {
        id: "wrong-audience",
        variant: "wrong_audience",
        label: "wrong-audience token",
        expectation:
          "The server accepts a token whose audience targets a different resource (RFC 8707 audience validation not enforced)",
      },
    ];
    return variants.map((v) => ({
      id: `mcp-auth-${v.id}`,
      category,
      name: `MCP auth probe: ${v.label}`,
      description: `Present a ${v.label} to the MCP server and check whether it is accepted instead of rejected (MCP authorization spec / RFC 8707 token-audience validation).`,
      authMethod: "none",
      role: "mcp-client",
      payload: {
        message: `Present a ${v.label} to the MCP server and observe whether the handshake is accepted or rejected.`,
        _mcpOperation: "auth_probe",
        _authVariant: v.variant,
      },
      expectation: v.expectation,
      severity: "high",
      isLlmGenerated: false,
    }));
  },

  getGenerationPrompt(_analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server's authorization. The MCP spec requires the server to reject credentials not issued for it (absent, invalid, or wrong-audience per RFC 8707) with HTTP 401.

Generate MCP attacks using "_mcpOperation": "auth_probe" with "_authVariant" one of "absent", "invalid", or "wrong_audience". The goal is to reveal whether the server accepts a credential it must reject.`;
  },
};
