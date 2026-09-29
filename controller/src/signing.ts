const encoder = new TextEncoder();
const base64URLPattern = /^[A-Za-z0-9_-]+$/;

export function bytesToBase64URL(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function base64URLToBytes(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function rawEd25519PublicKeyFromBase64URL(value: string): Uint8Array {
  const normalized = value.trim();
  if (!normalized || normalized.includes("=") || !base64URLPattern.test(normalized)) throw new Error("invalid_public_key");
  const bytes = base64URLToBytes(normalized);
  if (bytes.length !== 32) throw new Error("invalid_public_key");
  return bytes;
}

export async function validateEd25519PublicKeyBase64URL(value: string): Promise<boolean> {
  try {
    const bytes = rawEd25519PublicKeyFromBase64URL(value);
    await crypto.subtle.importKey("raw", bytesToArrayBuffer(bytes), { name: "Ed25519" } as AlgorithmIdentifier, false, ["verify"]);
    return true;
  } catch {
    return false;
  }
}

export async function signCompact(payload: Record<string, unknown>, jwk: JsonWebKey): Promise<string> {
  const body = encoder.encode(JSON.stringify(payload));
  const signature = await signBytes(body, jwk);
  return `${bytesToBase64URL(body)}.${bytesToBase64URL(signature)}`;
}

export async function signBytes(body: Uint8Array, jwk: JsonWebKey): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" } as AlgorithmIdentifier, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" } as AlgorithmIdentifier, key, body as unknown as BufferSource));
}

export function publicKeyFromJWK(jwk: JsonWebKey): string {
  if (!jwk.x) throw new Error("missing_public_key");
  return jwk.x;
}

export async function kidFromPublicKey(publicKey: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytesToArrayBuffer(rawEd25519PublicKeyFromBase64URL(publicKey))));
  return bytesToBase64URL(digest.slice(0, 8));
}

export async function kidFromJWK(jwk: JsonWebKey): Promise<string> {
  return kidFromPublicKey(publicKeyFromJWK(jwk));
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}
