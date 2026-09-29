import { describe, expect, it } from "vitest";
import { encodeInitString } from "../src/init-string";

const KEY = "lginit_8PVlu4Av1d_J8h5Ri06dAon4t8KK_izFqW-nGXQqNC8";

describe("init string", () => {
  it("emits the compact form (https omitted, port only when non-default)", () => {
    expect(encodeInitString("https://lg.example.com", KEY)).toBe(`lg.example.com/${KEY}`);
    expect(encodeInitString("https://lg.example.com/", KEY)).toBe(`lg.example.com/${KEY}`);
    expect(encodeInitString("https://lg.example.com:443", KEY)).toBe(`lg.example.com/${KEY}`);
    expect(encodeInitString("https://lg.example.com:8443", KEY)).toBe(`lg.example.com:8443/${KEY}`);
    // A non-https origin keeps its scheme (local/dev deployments).
    expect(encodeInitString("http://lg-worker:8787", KEY)).toBe(`http://lg-worker:8787/${KEY}`);
    expect(encodeInitString("http://lg-worker:80", KEY)).toBe(`http://lg-worker/${KEY}`);
    expect(encodeInitString("https://[2001:db8::1]:8443", KEY)).toBe(`[2001:db8::1]:8443/${KEY}`);
  });
});
