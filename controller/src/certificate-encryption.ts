import { base64URLToBytes, bytesToBase64URL, sha256Hex } from "./signing";

const P256_PUBLIC_KEY_BYTES = 65;
const AES_GCM_IV_BYTES = 12;

export interface CertificateEnvelope {
  alg: "ECDH-P256+A256GCM";
  epk: string;
  iv: string;
  ciphertext: string;
}

export async function validateP256PublicKeyBase64URL(value: string): Promise<boolean> {
  try {
    await importP256PublicKey(value);
    return true;
  } catch {
    return false;
  }
}

export async function encryptForP256PublicKey(payload: string, publicKeyBase64URL: string): Promise<CertificateEnvelope> {
  const recipient = await importP256PublicKey(publicKeyBase64URL);
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: recipient },
    ephemeral.privateKey,
    256,
  );
  const keyMaterial = await crypto.subtle.digest("SHA-256", shared);
  const aesKey = await crypto.subtle.importKey("raw", keyMaterial, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = new Uint8Array(AES_GCM_IV_BYTES);
  crypto.getRandomValues(iv);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(payload));
  const epk = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  return {
    alg: "ECDH-P256+A256GCM",
    epk: bytesToBase64URL(epk),
    iv: bytesToBase64URL(iv),
    ciphertext: bytesToBase64URL(new Uint8Array(ciphertext)),
  };
}

export async function p256KeyID(publicKeyBase64URL: string): Promise<string> {
  return (await sha256Hex(publicKeyBase64URL)).slice(0, 16);
}

async function importP256PublicKey(value: string): Promise<CryptoKey> {
  const normalized = value.trim();
  const bytes = base64URLToBytes(normalized);
  if (bytes.length !== P256_PUBLIC_KEY_BYTES || bytes[0] !== 4) throw new Error("invalid_p256_public_key");
  return crypto.subtle.importKey(
    "raw",
    bytesToArrayBuffer(bytes),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
}

function bytesToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}
