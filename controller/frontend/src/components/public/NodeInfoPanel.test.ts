import { describe, expect, it } from "vitest";
import { buildRttTargets, defaultRttTargetKeys, resolveNodeAction } from "./NodeInfoPanel";

describe("RTT targets", () => {
  it("uses Cloudflare plus selected node v4/v6 by default without primary domain", () => {
    const nodes = [{
      id: "testnode01",
      domain: "testnode01.lgtest-node.example",
      domain_v4: "testnode01.lgtest-node-v4.example",
      domain_v6: "testnode01.lgtest-node-v6.example",
      has_ipv4: true,
      has_ipv6: true,
    }];
    const targets = buildRttTargets(nodes, "testnode01");

    expect(targets.map((target) => target.url)).toEqual([
      "https://cp.cloudflare.com/generate_204",
      "https://www.google.com/generate_204",
      "https://testnode01.lgtest-node-v4.example/generate_204",
      "https://testnode01.lgtest-node-v6.example/generate_204",
    ]);
    expect(defaultRttTargetKeys(targets)).toEqual(new Set(["cf", "testnode01:ipv4", "testnode01:ipv6"]));
  });

  it("prefers generic action fields but falls back to legacy buy fields", () => {
    expect(resolveNodeAction({
      action_url: "https://example.com/detail",
      action_label: "Detail",
      buy_url: "https://example.com/buy",
      buy_label: "Buy",
    })).toEqual({
      actionUrl: "https://example.com/detail",
      actionLabel: "Detail",
    });

    expect(resolveNodeAction({
      buy_url: "https://example.com/buy",
      buy_label: "Buy",
    })).toEqual({
      actionUrl: "https://example.com/buy",
      actionLabel: "Buy",
    });
  });

  it("drops executable or protocol-relative action links", () => {
    expect(resolveNodeAction({ buy_url: "javascript:alert(1)" }).actionUrl).toBe("");
    expect(resolveNodeAction({ buy_url: "//attacker.example/path" }).actionUrl).toBe("");
    expect(resolveNodeAction({ buy_url: "http://example.com/path" }).actionUrl).toBe("http://example.com/path");
    expect(resolveNodeAction({ buy_url: "/pricing" }).actionUrl).toBe("/pricing");
  });
});
