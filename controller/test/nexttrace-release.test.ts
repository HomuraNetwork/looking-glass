import { describe, expect, it } from "vitest";
import { fetchNexttraceRelease } from "../src/nexttrace-release";

describe("NextTrace release metadata", () => {
  it("uses GitHub API digests for supported assets", async () => {
    const response = {
      tag_name: "v1.7.3",
      assets: [
        { name: "nexttrace_linux_amd64", digest: `sha256:${"a".repeat(64)}`, size: 42 },
        { name: "nexttrace_linux_arm64", digest: `sha256:${"b".repeat(64)}`, size: 42 },
      ],
    };
    const result = await fetchNexttraceRelease(async (input, init) => {
      expect(String(input)).toBe("https://api.github.com/repos/nxtrace/NTrace-core/releases/latest");
      expect(new Headers(init?.headers).get("user-agent")).toBe("HLG-Controller");
      return new Response(JSON.stringify(response));
    });
    expect(result.map((asset) => [asset.arch, asset.sha256])).toEqual([["amd64", "a".repeat(64)], ["arm64", "b".repeat(64)]]);
  });

  it("fails closed if GitHub does not publish a valid digest", async () => {
    const response = { tag_name: "v1.7.3", assets: [
      { name: "nexttrace_linux_amd64", digest: null, size: 42 },
      { name: "nexttrace_linux_arm64", digest: `sha256:${"b".repeat(64)}`, size: 42 },
    ] };
    await expect(fetchNexttraceRelease(async () => new Response(JSON.stringify(response)))).rejects.toThrow("missing a valid SHA-256 digest");
  });
});
