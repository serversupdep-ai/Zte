import { checkDomains, DEFAULT_TLDS, type DomainResult } from "./domains";
import { checkAppStore, checkPlayStore, type StoreResult } from "./stores";
import { checkWeb, searchLinks, type WebResult } from "./web";
import { checkGithub, type GithubResult } from "./github";
import { trademarkLinks, NICE_CLASSES, type RegisterLink } from "./trademarks";

export interface FullCheck {
  name: string;
  domains: DomainResult[];
  stores: StoreResult[];
  web: WebResult;
  trademarks: { classes: typeof NICE_CLASSES; links: RegisterLink[] };
  /** Only present when requested (MCP). */
  github?: GithubResult;
}

export async function checkAll(
  name: string,
  tlds: string[] = DEFAULT_TLDS,
  country = "de",
  opts: { web?: boolean; github?: boolean } = {},
): Promise<FullCheck> {
  const [domains, apple, play, web, github] = await Promise.all([
    checkDomains(name, tlds),
    checkAppStore(name, country),
    checkPlayStore(name, country),
    opts.web === false ? Promise.resolve({ provider: "links" as const, query: `"${name}"`, hits: [], links: searchLinks(name) }) : checkWeb(name),
    opts.github ? checkGithub(name) : Promise.resolve(undefined),
  ]);
  return {
    name,
    domains,
    stores: [apple, play],
    web,
    trademarks: { classes: NICE_CLASSES, links: trademarkLinks(name) },
    ...(github ? { github } : {}),
  };
}
