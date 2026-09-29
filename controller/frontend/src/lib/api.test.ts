import { describe, expect, it, vi } from "vitest";
import {
  buildAdminNodePayload,
  buildDownloadTokenPayload,
  buildDownloadURL,
  buildIperfSessionPayload,
  buildIperfWSURL,
  buildLiveSessionPayload,
  buildLiveWSURL,
  closeIperfSession,
  buildJobLiveWSURL,
  buildJobWSURL,
  listAdminProjectSettings,
  listAdminNodes,
  loginAdmin,
  requestLiveSession,
  resetAdminProjectSetting,
  saveAdminProjectSetting,
} from "./api";
import type { AdminNodeFormInput } from "./api";

describe("agent URL builders", () => {
  it("builds required public endpoint paths", () => {
    vi.stubGlobal("location", { protocol: "https:", host: "lg.example.net" });
    const node = { id: "testnode01", domain: "testnode01.lgtest-node.example" };
    expect(buildDownloadURL(node, "tok.sig", "10M")).toBe(
      "https://testnode01.lgtest-node.example/download/tok.sig/10M",
    );
    expect(buildJobWSURL(node, "tok.sig")).toBe(
      "wss://lg.example.net/api/jobs/ws?node=testnode01&token=tok.sig",
    );
    expect(buildLiveWSURL(node, "sess.sig")).toBe(
      "wss://lg.example.net/api/jobs/live?node=testnode01&token=sess.sig",
    );
    expect(buildJobLiveWSURL(node)).toBe("wss://lg.example.net/api/jobs/live?node=testnode01");
    expect(buildIperfWSURL(node, "ipf_123")).toBe(
      "wss://lg.example.net/api/iperf/session/ws?node=testnode01&session_id=ipf_123",
    );
    vi.unstubAllGlobals();
  });

  it("builds iperf session payloads for UDP reverse commands", () => {
    expect(
      buildIperfSessionPayload({
        node: "testnode01",
        mode: "udp",
        reverse: true,
        duration: 30,
        parallel: 4,
        turnstileToken: "captcha-token",
      }),
    ).toEqual({
      node: "testnode01",
      mode: "udp",
      reverse: true,
      duration: 30,
      parallel: 4,
      direction: "reverse",
      turnstile_token: "captcha-token",
    });
  });

  it("posts iPerf close requests to the Worker API", async () => {
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path: string, init?: RequestInit) => {
        calls.push({ path, init });
        return new Response(JSON.stringify({ ok: true, status: "closed_by_request" }), {
          headers: { "content-type": "application/json" },
        });
      }),
    );

    await closeIperfSession("testnode01", "ipf_123");

    expect(calls[0].path).toBe("/api/iperf/session/close");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ node: "testnode01", session_id: "ipf_123" });
    vi.unstubAllGlobals();
  });

  it("builds download token payloads with Turnstile response tokens", () => {
    expect(buildDownloadTokenPayload("testnode01", "captcha-token")).toEqual({
      node: "testnode01",
      turnstile_token: "captcha-token",
    });
    expect(buildDownloadTokenPayload("testnode01", "captcha-token", "100M")).toEqual({
      node: "testnode01",
      size: "100M",
      turnstile_token: "captcha-token",
    });
  });

  it("builds live session payloads with an optional Turnstile response token", () => {
    expect(buildLiveSessionPayload("testnode01", "captcha-token")).toEqual({
      node: "testnode01",
      turnstile_token: "captcha-token",
    });
    expect(buildLiveSessionPayload("testnode01")).toEqual({
      node: "testnode01",
      turnstile_token: undefined,
    });
  });

  it("requests a live session token from the worker", async () => {
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path: string, init?: RequestInit) => {
        calls.push({ path, init });
        return new Response(JSON.stringify({ token: "sess.sig", expires_at: 1780301800, node: "testnode01", domain: "testnode01.lgtest-node.example" }), {
          headers: { "content-type": "application/json" },
        });
      }),
    );

    const session = await requestLiveSession("testnode01", "captcha-token");

    expect(calls[0].path).toBe("/api/jobs/live-session");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ node: "testnode01", turnstile_token: "captcha-token" });
    expect(session.token).toBe("sess.sig");
    expect(session.expires_at).toBe(1780301800);
    vi.unstubAllGlobals();
  });

  it("normalizes one admin node payload and applies DNS and feature options", () => {
    // Runtime form/settings data can contain whitespace or unknown features,
    // so exercise all payload normalization through one representative node.
    const input: AdminNodeFormInput = {
      id: " node-a ",
      domain: " node-a.example.test ",
      port: 8443,
      domain_v4: " v4.node-a.example.test ",
      domain_v6: " v6.node-a.example.test ",
      display_name: " Node A ",
      display_label: " A ",
      public_ipv4: " 203.0.113.10 ",
      public_ipv6: "",
      description: "",
      buy_url: "",
      buy_label: "",
      bgp_url: "",
      dynamic_ip: false,
      profile_id: "",
      enabled: true,
      hidden: false,
      maintenance: true,
      features: ["generate204", "bogus", "ping", ""] as AdminNodeFormInput["features"],
    };

    expect(buildAdminNodePayload(input, { enabled: true, mode: "id" })).toEqual({
      id: "node-a",
      domain: "node-a.example.test",
      port: 8443,
      domain_v4: "v4.node-a.example.test",
      domain_v6: "v6.node-a.example.test",
      display_name: "Node A",
      display_label: "A",
      public_ipv4: "203.0.113.10",
      public_ipv6: "",
      description: "",
      buy_url: "",
      buy_label: "",
      bgp_url: "",
      dynamic_ip: false,
      profile_id: "default",
      enabled: true,
      hidden: false,
      maintenance: true,
      features: ["generate204", "ping"],
      auto_dns: true,
      dns_mode: "id",
    });
    const manualDNS = buildAdminNodePayload(input, { enabled: false, mode: "full" });
    expect(manualDNS).toMatchObject({ auto_dns: false, features: ["generate204", "ping"] });
    expect(manualDNS).not.toHaveProperty("dns_mode");
  });

  it("uses cookie sessions for admin API calls", async () => {
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path: string, init?: RequestInit) => {
        calls.push({ path, init });
        if (path === "/api/admin/login") {
          return new Response(JSON.stringify({ authenticated: true, onboarding_required: false, user: { username: "admin" } }), {
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ nodes: [] }), { headers: { "content-type": "application/json" } });
      }),
    );

    await loginAdmin({ username: "admin", password: "local-admin-pass" });
    await listAdminNodes();

    expect(calls.map((call) => call.init?.credentials)).toEqual(["same-origin", "same-origin"]);
    expect(calls.some((call) => new Headers(call.init?.headers).has("authorization"))).toBe(false);
    vi.unstubAllGlobals();
  });

  it("uses cookie sessions for admin project settings", async () => {
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path: string, init?: RequestInit) => {
        calls.push({ path, init });
        if (path === "/api/admin/project-settings" && init?.method === "POST") {
          return new Response(
            JSON.stringify({ key: "LG_BLOCK_PRIVATE_IPS", label: "Block Private IPs", type: "boolean", value: true, configured: true, source: "d1" }),
            { headers: { "content-type": "application/json" } },
          );
        }
        return new Response(
          JSON.stringify({
            settings: [{ key: "LG_BLOCK_PRIVATE_IPS", label: "Block Private IPs", type: "boolean", value: true, configured: true, source: "d1" }],
          }),
          { headers: { "content-type": "application/json" } },
        );
      }),
    );

    await listAdminProjectSettings();
    await saveAdminProjectSetting("LG_BLOCK_PRIVATE_IPS", true);
    await resetAdminProjectSetting("LG_BLOCK_PRIVATE_IPS", "LG_BLOCK_PRIVATE_IPS");

    expect(calls.map((call) => call.init?.credentials)).toEqual(["same-origin", "same-origin", "same-origin"]);
    expect(calls.some((call) => new Headers(call.init?.headers).has("authorization"))).toBe(false);
    vi.unstubAllGlobals();
  });
});
