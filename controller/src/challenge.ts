import { clientIP } from "./http";
import { getBooleanProjectSetting } from "./project-settings";
import { readRuntimeSecretStrict } from "./runtime-secrets";
import type { SqlDatabase } from "./runtime";

export type ChallengeStatus = "success" | "required" | "invalid" | "unavailable" | "error";

export interface ChallengeResult {
  status: ChallengeStatus;
  provider: "turnstile";
  detail?: string;
}

export interface ChallengeVerifier {
  verify(input: { token?: string; request: Request; idempotencyKey?: string }): Promise<ChallengeResult>;
}

export function createChallengeVerifier(db: SqlDatabase | undefined): ChallengeVerifier {
  return new TurnstileChallengeVerifier(db);
}

export function challengeError(status: ChallengeStatus): string {
  switch (status) {
    case "required":
      return "turnstile_required";
    case "invalid":
      return "turnstile_invalid";
    case "unavailable":
      return "turnstile_unavailable";
    default:
      return "turnstile_error";
  }
}

export function challengeStatusCode(status: ChallengeStatus): number {
  switch (status) {
    case "required":
    case "invalid":
      return 403;
    case "unavailable":
      return 503;
    default:
      return 502;
  }
}

class TurnstileChallengeVerifier implements ChallengeVerifier {
  constructor(private readonly db: SqlDatabase | undefined) {}

  async verify(input: { token?: string; request: Request; idempotencyKey?: string }): Promise<ChallengeResult> {
    const secretRead = await readRuntimeSecretStrict(this.db, "TURNSTILE_SECRET_KEY");
    if (secretRead.dbError) {
      // Fail closed on D1 infra errors: an unreadable secret must be
      // distinguishable from "Turnstile unconfigured".
      return { status: "error", provider: "turnstile", detail: "secret_read_failed" };
    }

    const turnstileSecret = secretRead.value;
    if (!turnstileSecret) {
      // Default is fail-open for operators who have not opted into Turnstile.
      // TURNSTILE_ENFORCED=true flips this to fail closed (unavailable) so a
      // missing secret cannot silently disable verification.
      if (await getBooleanProjectSetting(this.db, "TURNSTILE_ENFORCED")) {
        return { status: "unavailable", provider: "turnstile", detail: "secret_missing_while_enforced" };
      }
      return { status: "success", provider: "turnstile" };
    }

    const token = input.token?.trim();
    if (!token) return { status: "required", provider: "turnstile" };

    const form = new FormData();
    form.set("secret", turnstileSecret);
    form.set("response", token);
    form.set("remoteip", clientIP(input.request));
    form.set("idempotency_key", input.idempotencyKey || crypto.randomUUID());

    let response: Response;
    try {
      response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        body: form,
        signal: AbortSignal.timeout(5000),
      });
    } catch {
      return { status: "error", provider: "turnstile", detail: "siteverify_fetch_failed" };
    }

    if (!response.ok) {
      return { status: "error", provider: "turnstile", detail: `siteverify_http_${response.status}` };
    }

    const payload = (await response.json()) as {
      success?: boolean;
      hostname?: string;
      challenge_ts?: string;
      "error-codes"?: string[];
    };
    if (payload.success === true) {
      const requestHost = new URL(input.request.url).hostname.toLowerCase();
      if (!payload.hostname || payload.hostname.toLowerCase() !== requestHost) {
        return { status: "invalid", provider: "turnstile", detail: "hostname_mismatch" };
      }
      const challengeTime = payload.challenge_ts ? Date.parse(payload.challenge_ts) : Number.NaN;
      const ageMs = Date.now() - challengeTime;
      if (!Number.isFinite(challengeTime) || ageMs > 5 * 60_000 || ageMs < -60_000) {
        return { status: "invalid", provider: "turnstile", detail: "challenge_timestamp_invalid" };
      }
      return { status: "success", provider: "turnstile" };
    }
    return {
      status: "invalid",
      provider: "turnstile",
      detail: payload["error-codes"]?.join(",") || "siteverify_rejected",
    };
  }
}
