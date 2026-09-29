import { Env } from "./config";
import { handleRequest, runScheduledPass } from "./app";
import { cfSockets, cfTcp, cfTransformHTML } from "./runtime/cloudflare";

/**
 * Cloudflare Workers entry point.
 *
 * All request routing and cron logic lives in app.ts and is runtime-neutral; this
 * file only wires the Cloudflare platform capabilities (WebSocketPair,
 * HTMLRewriter, ctx.waitUntil) into the core.
 */
export default {
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runScheduledPass(env));
  },

  async fetch(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
    return handleRequest(request, env, {
      sockets: cfSockets,
      tcp: cfTcp,
      transformHTML: cfTransformHTML,
      waitUntil: ctx ? (task) => ctx.waitUntil(task) : undefined,
    });
  },
};
