import { describe, it, expect } from "vitest";
import {
  tamperHeaders,
  buildWrongAudienceJwt,
  parseHttpStatus,
} from "../lib/mcp/auth-probe.js";

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const part = jwt.split(".")[1];
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

describe("tamperHeaders", () => {
  const base = { "x-api-key": "votal_live_secret", "content-type": "application/json" };

  it("drops the auth header for the 'absent' variant", () => {
    const out = tamperHeaders(base, "absent");
    expect(out["x-api-key"]).toBeUndefined();
    expect(out["content-type"]).toBe("application/json"); // non-auth preserved
  });

  it("replaces the credential for the 'invalid' variant", () => {
    const out = tamperHeaders(base, "invalid");
    expect(out["x-api-key"]).toBe("rt-invalid-credential-00000000");
  });

  it("swaps a Bearer token for a wrong-audience JWT", () => {
    const out = tamperHeaders({ authorization: "Bearer real.jwt.here" }, "wrong_audience");
    expect(out.authorization).toMatch(/^Bearer /);
    const jwt = out.authorization.replace(/^Bearer /, "");
    expect(decodeJwtPayload(jwt).aud).toBe("urn:red-team:wrong-audience");
  });
});

describe("buildWrongAudienceJwt", () => {
  it("produces a well-formed JWT with a wrong audience and a far-future exp", () => {
    const jwt = buildWrongAudienceJwt();
    expect(jwt.split(".")).toHaveLength(3);
    const payload = decodeJwtPayload(jwt);
    expect(payload.aud).toBe("urn:red-team:wrong-audience");
    expect(Number(payload.exp)).toBeGreaterThan(4_000_000_000);
  });
});

describe("parseHttpStatus", () => {
  it("extracts the status from a transport error", () => {
    expect(parseHttpStatus('MCP HTTP 401 for "initialize": unauthorized')).toBe(401);
  });
  it("returns 0 when no status is present", () => {
    expect(parseHttpStatus("Connection refused")).toBe(0);
  });
});
