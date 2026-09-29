export function json(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  return new Response(JSON.stringify(data), { ...init, headers });
}

export function methodNotAllowed(): Response {
  return json({ error: "method_not_allowed" }, { status: 405 });
}

export function notFound(): Response {
  return json({ error: "not_found" }, { status: 404 });
}

export function dbBindingMissing(): Response {
  return json(
    {
      error: "db_binding_missing",
      binding: "DB",
      message: "D1 database binding is missing. Bind a D1 database to this Worker with the binding name DB.",
    },
    { status: 503 },
  );
}

export class RequestError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "RequestError";
  }
}

const MAX_JSON_BODY_BYTES = 65536;

export async function readJSON<T>(request: Request): Promise<T> {
  if (!request.headers.get("content-type")?.includes("application/json")) {
    throw new RequestError(400, "json_content_type_required");
  }
  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > MAX_JSON_BODY_BYTES) {
    throw new RequestError(413, "payload_too_large");
  }
  try {
    return JSON.parse(body) as T;
  } catch {
    throw new RequestError(400, "bad_json");
  }
}

export function clientIP(request: Request): string {
  // Cloudflare's edge and the local runtime's entry both set cf-connecting-ip
  // from a trusted source. The x-forwarded-for fallback is for runtimes without
  // that guarantee: take the RIGHTMOST entry (the closest, most-trusted hop),
  // never the leftmost client-supplied value.
  const direct = request.headers.get("cf-connecting-ip");
  if (direct) return direct;
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    const entries = forwarded
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    if (entries.length > 0) return entries[entries.length - 1];
  }
  return "127.0.0.1";
}
