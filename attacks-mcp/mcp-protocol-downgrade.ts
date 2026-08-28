import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";
import { PROTOCOL_DOWNGRADE_VARIANTS } from "../lib/mcp/protocol-probe.js";

const category = "mcp_protocol_downgrade" as const;

/**
 * MCP Protocol Downgrade.
 *
 * At `initialize` the client advertises a `protocolVersion`. A well-behaved
 * server responds with the same version (if supported) or negotiates to a
 * supported one; the spec (2025-06-18) also requires HTTP servers to reject an
 * unsupported `MCP-Protocol-Version`. A server that instead ECHOES an
 * unsupported / garbage version verbatim is not validating the protocol
 * contract and will operate under an unknown or downgraded protocol — which can
 * silently disable security features introduced in later revisions.
 *
 * Each seed advertises one unsupported version via the `protocol_probe`
 * operation (its own short-lived session); the analyzer grades an echoed-back
 * version as a downgrade (PASS) and a rejection/negotiation as secure (FAIL).
 */
export const mcpProtocolDowngradeModule: AttackModule = {
  category,

  getSeedAttacks(_analysis?: CodebaseAnalysis): Attack[] {
    return PROTOCOL_DOWNGRADE_VARIANTS.map((v) => ({
      id: `mcp-protodown-${v.id}`,
      category,
      name: `MCP protocol downgrade: ${v.label}`,
      description: `Advertise a ${v.label} ("${v.version}") at initialize and observe whether the server rejects/negotiates it or echoes it back and operates under it.`,
      authMethod: "none",
      role: "mcp-client",
      payload: {
        message: `Advertise the ${v.label} "${v.version}" at MCP initialize and observe whether the handshake is rejected, negotiated, or accepted verbatim.`,
        _mcpOperation: "protocol_probe",
        _protocolVariant: v.id,
        _protocolVersion: v.version,
      },
      expectation: v.expectation,
      severity: "high",
      isLlmGenerated: false,
    }));
  },

  getGenerationPrompt(_analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server's protocol-version handling.

At initialize the client sends a protocolVersion. A compliant server rejects an unsupported version or negotiates to a supported one; echoing an unsupported/garbage version back verbatim means the server is not validating the protocol contract and may operate under a downgraded protocol that lacks later security features.

Generate MCP attacks using "_mcpOperation": "protocol_probe" with "_protocolVersion" set to an unsupported/garbage value (e.g. an ancient date, "9999-99-99", or a malformed string) and "_protocolVariant" as a short id. The goal is to reveal whether the server accepts and echoes a version it should reject.`;
  },
};
