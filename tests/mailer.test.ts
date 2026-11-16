import { afterEach, describe, expect, it, vi } from "vitest";
import { sendEmail } from "../lib/mailer.js";

const ORIGINAL = { RESEND_API_KEY: process.env.RESEND_API_KEY, EMAIL_FROM: process.env.EMAIL_FROM };

afterEach(() => {
  vi.unstubAllGlobals();
  for (const [key, value] of Object.entries(ORIGINAL)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe("sendEmail", () => {
  it("sends through the Resend API", async () => {
    process.env.RESEND_API_KEY = "re_test";
    process.env.EMAIL_FROM = "Red-Team AI <no-reply@example.com>";
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await sendEmail("user@company.com", "Hello", "Body");

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.resend.com/emails");
    expect(init.headers).toMatchObject({ Authorization: "Bearer re_test" });
    expect(JSON.parse(init.body as string)).toEqual({
      from: "Red-Team AI <no-reply@example.com>",
      to: ["user@company.com"],
      subject: "Hello",
      text: "Body",
    });
  });

  it("logs a Resend error instead of throwing", async () => {
    process.env.RESEND_API_KEY = "re_test";
    vi.stubGlobal("fetch", vi.fn(async () => new Response("bad domain", { status: 422 })));
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(sendEmail("user@company.com", "Hello", "Body")).resolves.toBeUndefined();
    expect(errors.mock.calls[0][0]).toMatch(/Resend rejected.*422/);
    errors.mockRestore();
  });

  it("prints instead of sending without an API key", async () => {
    delete process.env.RESEND_API_KEY;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const logs = vi.spyOn(console, "log").mockImplementation(() => {});

    await sendEmail("user@company.com", "Hello", "Body");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(logs.mock.calls[0][0]).toMatch(/not sending/);
    logs.mockRestore();
  });
});
