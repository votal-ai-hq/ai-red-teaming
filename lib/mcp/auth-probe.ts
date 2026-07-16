/**
 * MCP token-audience / confused-deputy probe helpers.
 *
 * Normative basis (verified primary sources): the MCP authorization spec
 * (2025-11-25) and security_best_practices (2025-06-18) require that an MCP
 * server "MUST validate that access tokens were issued specifically for them as
 * the intended audience" (RFC 8707), "MUST NOT accept any tokens that were not
 * explicitly issued for the MCP server", and "Invalid or expired tokens MUST
 * receive an HTTP 401 response". Token passthrough is an explicitly forbidden
 * anti-pattern and the core of the MCP confused-deputy problem.
 *
 * A direct-client scanner can test the black-box half of this: present a
 * credential that the server MUST reject (absent / invalid / wrong-audience)
 * and assert rejection. Acceptance is a finding.
 *
 * Pure and dependency-free so it is unit-testable.
 */

export type AuthVariant = "absent" | "invalid" | "wrong_audience";

/** Header names that carry an auth credential. */
const AUTH_HEADER =
  /^(authorization|x-api-key|api[-_]?key|x-auth-token|x-access-token|x-api-token)$/i;

/**
 * Return a copy of `headers` with any auth credential tampered per the variant:
 * - absent: drop the auth header entirely (tests whether auth is required)
 * - invalid: replace with a clearly-invalid value (tests token validation)
 * - wrong_audience: replace a Bearer/JWT with a well-formed token whose `aud`
 *   claim targets a different resource (tests RFC 8707 audience validation)
 */
export function tamperHeaders(
  headers: Record<string, string>,
  variant: AuthVariant,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!AUTH_HEADER.test(key)) {
      out[key] = value;
      continue;
    }
    if (variant === "absent") continue; // drop the credential
    if (variant === "invalid") {
      out[key] = "rt-invalid-credential-00000000";
      continue;
    }
    // wrong_audience
    out[key] = /^bearer\s/i.test(value)
      ? `Bearer ${buildWrongAudienceJwt()}`
      : buildWrongAudienceJwt();
  }
  return out;
}

/**
 * A well-formed (unsigned, alg:none) JWT whose audience is a DIFFERENT resource.
 * A spec-compliant server must reject it on audience validation (RFC 8707)
 * regardless of signature; acceptance indicates missing audience checks.
 * Uses a fixed far-future `exp` so the token is not "expired" — isolating the
 * audience check as the reason for any rejection.
 */
export function buildWrongAudienceJwt(): string {
  const b64 = (o: unknown) =>
    Buffer.from(JSON.stringify(o)).toString("base64url");
  const header = b64({ alg: "none", typ: "JWT" });
  const payload = b64({
    sub: "red-team-probe",
    aud: "urn:red-team:wrong-audience",
    iss: "red-team-scanner",
    exp: 4102444800, // 2100-01-01, fixed so the token is never expired
  });
  return `${header}.${payload}.`;
}

export interface AuthProbeResult {
  variant: AuthVariant;
  /** Did the server ACCEPT the credential it should have rejected? */
  accepted: boolean;
  statusCode: number;
  detail: string;
}

/** Parse the HTTP status the streamable_http transport embeds in its error. */
export function parseHttpStatus(errorMessage: string): number {
  const m = errorMessage.match(/HTTP (\d{3})/);
  return m ? Number(m[1]) : 0;
}
