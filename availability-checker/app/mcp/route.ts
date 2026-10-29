import { createMcpHandler } from "mcp-handler";
import { z } from "zod";
import { checkAll } from "@/lib/check";
import { checkDomains, DEFAULT_TLDS } from "@/lib/domains";
import { suggestDomains } from "@/lib/suggest";
import { checkAppStore, checkPlayStore } from "@/lib/stores";
import { checkWeb } from "@/lib/web";
import { trademarkLinks, NICE_CLASSES } from "@/lib/trademarks";
import { cleanName } from "@/lib/util";
import { checkGithub } from "@/lib/github";
import { checkMany, MAX_BATCH } from "@/lib/batch";

export const maxDuration = 60;

const json = (data: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] });
const nameSchema = z.string().min(1).max(40).describe("Brand / product name to check");

const handler = createMcpHandler(
  (server) => {
    server.registerTool(
      "check_name",
      {
        title: "Check a name everywhere",
        description:
          "Runs all checks for a candidate name: domains, Apple App Store, Google Play, exact-phrase web search and trademark register links (DPMA, EUIPO, TMview, WIPO).",
        inputSchema: z.object({
          name: nameSchema,
          tlds: z.array(z.string()).optional().describe(`TLDs to check, default ${DEFAULT_TLDS.join(", ")}`),
          github: z.boolean().optional().describe("Also check GitHub handle and repo names"),
        }),
      },
      async ({ name, tlds, github }) => json(await checkAll(cleanName(name), tlds?.length ? tlds : DEFAULT_TLDS, "de", { github })),
    );

    server.registerTool(
      "check_names",
      {
        title: "Check a list of names",
        description: `Batch checker for a shortlist (up to ${MAX_BATCH} names). Checks domains and Apple App Store / Google Play for every name in parallel and returns a ranking, best candidate first, with a 0-100 score, free and taken domains, store verdicts and notes. Set details=true for the full per-name data. Run trademark_links on the winners afterwards.`,
        inputSchema: z.object({
          names: z.array(nameSchema).min(1).max(MAX_BATCH).describe("Candidate names"),
          tlds: z.array(z.string()).optional().describe(`TLDs to check, default ${DEFAULT_TLDS.join(", ")}`),
          country: z.string().length(2).optional().describe("Store country, default de"),
          details: z.boolean().optional().describe("Include the full per-name results"),
          github: z.boolean().optional().describe("Also check GitHub handle and repo names (not part of the score). More than ~8 names needs GITHUB_TOKEN on the server."),
        }),
      },
      async ({ names, tlds, country, details, github }) => json(await checkMany(names, { tlds, country, details, github })),
    );

    server.registerTool(
      "check_domains",
      {
        title: "Check domain availability",
        description: "Checks <name>.<tld> via RDAP (authoritative) with a DNS fallback. status is available | taken | unknown.",
        inputSchema: z.object({ name: nameSchema, tlds: z.array(z.string()).optional() }),
      },
      async ({ name, tlds }) => json(await checkDomains(name, tlds?.length ? tlds : DEFAULT_TLDS)),
    );

    server.registerTool(
      "suggest_domains",
      {
        title: "Suggest free domains",
        description: "Tries alternative TLDs, prefixes (get, try, use...) and suffixes (app, hq, labs...) and returns the variants that look available.",
        inputSchema: z.object({ name: nameSchema, limit: z.number().int().min(1).max(30).optional() }),
      },
      async ({ name, limit }) => json(await suggestDomains(cleanName(name), limit ?? 12)),
    );

    server.registerTool(
      "check_app_stores",
      {
        title: "Check App Store and Google Play",
        description: "Searches Apple App Store and Google Play for listings with the same or a similar name. verdict: exact | similar | none.",
        inputSchema: z.object({ name: nameSchema, country: z.string().length(2).optional().describe("Store country, default de") }),
      },
      async ({ name, country }) => json(await Promise.all([checkAppStore(name, country ?? "de"), checkPlayStore(name, country ?? "de")])),
    );

    server.registerTool(
      "check_github",
      {
        title: "Check GitHub",
        description:
          "Checks whether the name is a free GitHub user/org handle and whether repositories with the same name exist (with stars). verdict: exact (an exact-name repo with 100+ stars) | similar (an exact-name repo exists) | none. Relevant for developer tools and open source.",
        inputSchema: z.object({ name: nameSchema }),
      },
      async ({ name }) => json(await checkGithub(cleanName(name))),
    );

    server.registerTool(
      "check_web",
      {
        title: "Exact-phrase web search",
        description:
          "Searches the web for the quoted name. Returns results and total count when GOOGLE_CSE_KEY/GOOGLE_CSE_CX or BRAVE_API_KEY is configured on the server, otherwise only search links.",
        inputSchema: z.object({ name: nameSchema }),
      },
      async ({ name }) => json(await checkWeb(name)),
    );

    server.registerTool(
      "trademark_links",
      {
        title: "Trademark register search links",
        description: `Links to DPMA, EUIPO, TMview and WIPO for the name. These registers have no free API, so a human or browsing agent must review them. Relevant Nice classes: ${NICE_CLASSES.map((c) => c.n).join(", ")}.`,
        inputSchema: z.object({ name: nameSchema }),
      },
      async ({ name }) => json({ classes: NICE_CLASSES, links: trademarkLinks(name) }),
    );
  },
  { serverInfo: { name: "namevet", version: "0.1.0" } },
);

// Optional shared secret: set MCP_AUTH_TOKEN to require "Authorization: Bearer <token>".
function guarded(req: Request) {
  const token = process.env.MCP_AUTH_TOKEN;
  if (token && req.headers.get("authorization") !== `Bearer ${token}`) {
    return new Response("Unauthorized", { status: 401 });
  }
  return handler(req);
}

export { guarded as GET, guarded as POST, guarded as DELETE };
