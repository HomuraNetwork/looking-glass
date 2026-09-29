import { describe, expect, it } from "vitest";
import {
  agentReleaseSigningInput,
  parseAgentManifest,
  type AgentReleaseDescriptor,
} from "../src/agent-release";
import { bytesToBase64URL } from "../src/signing";

/**
 * The release descriptor is what `hlg-agent update` trusts: the agent verifies
 * the controller's signature over `agentReleaseSigningInput` before it
 * downloads or replaces its binary. These pin the wire shape the Go verifier
 * (agent/internal/agentupdate) depends on, so a change here breaks loudly.
 */
describe("agent release descriptor", () => {
  const descriptor: AgentReleaseDescriptor = {
    build_id: "abc1234",
    target: "hlg-agent-linux-amd64",
    sha256: "a".repeat(64),
    size: 1234,
    path: "/_agent/binary/hlg-agent-linux-amd64",
    node_id: "node-internal-1",
    expires_at: 1800000000,
  };

  it("canonically joins the signed payload in a fixed order", () => {
    expect(agentReleaseSigningInput(descriptor)).toBe(
      [
        "hlg-agent-release",
        "abc1234",
        "hlg-agent-linux-amd64",
        "a".repeat(64),
        "1234",
        "/_agent/binary/hlg-agent-linux-amd64",
        "node-internal-1",
        "1800000000",
      ].join("\n"),
    );
  });

  it("is verifiable by an Ed25519 key (mirrors the Go/agent verification)", async () => {
    // A stand-in for signAgentRelease: sign the same bytes with a fresh key and
    // confirm a raw Ed25519 verify accepts it, which is exactly what the agent
    // does with the config_verify public key.
    const keyPair = (await crypto.subtle.generateKey({ name: "Ed25519" } as AlgorithmIdentifier, true, ["sign", "verify"])) as CryptoKeyPair;
    const publicKey = keyPair.publicKey;
    const privateKey = keyPair.privateKey;
    const message = new TextEncoder().encode(agentReleaseSigningInput(descriptor));
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" } as AlgorithmIdentifier, privateKey, message as unknown as BufferSource));
    expect(await crypto.subtle.verify({ name: "Ed25519" } as AlgorithmIdentifier, publicKey, signature as unknown as BufferSource, message as unknown as BufferSource)).toBe(true);
    // Tampering with any signed field invalidates the signature.
    const tampered = new TextEncoder().encode(agentReleaseSigningInput({ ...descriptor, sha256: "b".repeat(64) }));
    expect(await crypto.subtle.verify({ name: "Ed25519" } as AlgorithmIdentifier, publicKey, signature as unknown as BufferSource, tampered as unknown as BufferSource)).toBe(false);
    expect(bytesToBase64URL(signature)).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe("agent manifest parsing", () => {
  it("reads per-target digest and size from the build-time manifest", () => {
    const manifest = parseAgentManifest({
      build_id: "abc1234",
      targets: [
        { name: "hlg-agent-linux-amd64", sha256: "a".repeat(64), size_bytes: 100 },
        { name: "hlg-agent-linux-arm64", sha256: "b".repeat(64), size_bytes: 200 },
      ],
    });
    expect(manifest.build_id).toBe("abc1234");
    expect(manifest.targets["hlg-agent-linux-amd64"]).toEqual({ sha256: "a".repeat(64), size: 100 });
    expect(manifest.targets["hlg-agent-linux-arm64"]).toEqual({ sha256: "b".repeat(64), size: 200 });
  });

  it("ignores malformed entries and a missing manifest", () => {
    expect(parseAgentManifest(null)).toEqual({ build_id: null, targets: {} });
    const manifest = parseAgentManifest({
      build_id: "abc",
      targets: [{ name: "hlg-agent-linux-amd64" }, { sha256: "x", size_bytes: 1 }, "nope"],
    });
    expect(manifest.build_id).toBe("abc");
    expect(manifest.targets).toEqual({});
  });
});
