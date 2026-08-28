/**
 * MCP protocol-version negotiation probes.
 *
 * At `initialize` the client advertises a `protocolVersion`. A well-behaved
 * server either responds with the same version (if supported) or negotiates to
 * a version it does support; the MCP spec (2025-06-18) also requires HTTP
 * clients to send an `MCP-Protocol-Version` header on subsequent requests and
 * servers to reject an unsupported one. A server that instead ECHOES an
 * unsupported / garbage version verbatim is not validating the protocol
 * contract and will operate under an unknown or downgraded protocol — the
 * downgrade signal these probes surface. Pure + dependency-free for testing.
 */

/** A version string no compliant server should claim to support. */
export interface ProtocolDowngradeVariant {
  id: string;
  /** Value advertised as `protocolVersion` at initialize. */
  version: string;
  label: string;
  expectation: string;
}

export const PROTOCOL_DOWNGRADE_VARIANTS: ProtocolDowngradeVariant[] = [
  {
    id: "ancient",
    version: "2023-01-01",
    label: "ancient/unsupported version",
    expectation:
      "The server rejects or negotiates away an ancient unsupported protocol version instead of echoing it back and operating under it",
  },
  {
    id: "garbage",
    version: "9999-99-99",
    label: "garbage date version",
    expectation:
      "The server rejects a syntactically-date-shaped but nonexistent protocol version instead of accepting it",
  },
  {
    id: "malformed",
    version: "not-a-version",
    label: "malformed version string",
    expectation:
      "The server rejects a malformed, non-date protocol version instead of accepting it",
  },
];

export interface ProtocolProbeResult {
  variant: string;
  /** Version the probe advertised at initialize. */
  requested: string;
  /** Version the server responded with (its initialize result), if any. */
  negotiated?: string;
  /** Did the initialize handshake succeed at all? */
  accepted: boolean;
  /** Did the server echo our unsupported/garbage version verbatim? */
  echoedUnsupported: boolean;
  statusCode: number;
  detail: string;
}

/**
 * Grade a completed protocol probe.
 *  - handshake rejected → secure (FAIL, no vuln)
 *  - accepted AND server echoed our unsupported version → downgrade (PASS)
 *  - accepted AND server negotiated to a different version → compliant (FAIL)
 */
export function isProtocolDowngrade(result: ProtocolProbeResult): boolean {
  return result.accepted && result.echoedUnsupported;
}
