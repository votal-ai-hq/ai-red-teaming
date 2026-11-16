/**
 * Outgoing email via Resend (https://resend.com).
 * Without RESEND_API_KEY, emails are printed to the log instead (local dev only:
 * the log then contains the sign-up / reset links).
 */

const RESEND_URL = "https://api.resend.com/emails";

export async function sendEmail(
  to: string,
  subject: string,
  text: string,
): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.log(
      `  [mail] RESEND_API_KEY not set, not sending. To: ${to}\n  Subject: ${subject}\n\n${text}\n`,
    );
    return;
  }

  try {
    const res = await fetch(RESEND_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: process.env.EMAIL_FROM || "Red-Team AI <no-reply@votal.ai>",
        to: [to],
        subject,
        text,
      }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      console.error(
        `  [mail] Resend rejected email to ${to}: ${res.status} ${await res.text()}`,
      );
    }
  } catch (err) {
    console.error(
      `  [mail] Failed to send email to ${to}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}
