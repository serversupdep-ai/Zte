import { checkDomain, type DomainResult } from "./domains";
import { pmap, toLabel } from "./util";

const ALT_TLDS = ["com", "de", "app", "io", "co", "dev", "ai", "net", "org", "eu", "xyz", "me"];
const PREFIXES = ["get", "try", "use", "my", "go", "the"];
const SUFFIXES = ["app", "hq", "hub", "labs", "io", "now", "ly", "kit"];

export interface Suggestion extends DomainResult {
  /** Why this was proposed. */
  kind: "tld" | "prefix" | "suffix" | "hyphen";
}

export function candidates(name: string): { domain: string; kind: Suggestion["kind"] }[] {
  const label = toLabel(name);
  if (!label) return [];
  const out: { domain: string; kind: Suggestion["kind"] }[] = [];
  for (const t of ALT_TLDS) out.push({ domain: `${label}.${t}`, kind: "tld" });
  for (const p of PREFIXES) out.push({ domain: `${p}${label}.com`, kind: "prefix" });
  for (const s of SUFFIXES) out.push({ domain: `${label}${s}.com`, kind: "suffix" });
  const words = name.trim().split(/\s+/).map(toLabel).filter(Boolean);
  if (words.length > 1) {
    out.push({ domain: `${words.join("-")}.com`, kind: "hyphen" });
    out.push({ domain: `${words.join("-")}.de`, kind: "hyphen" });
  }
  return out;
}

/** Checks a pool of variants and returns the ones that look free. */
export async function suggestDomains(name: string, limit = 12): Promise<Suggestion[]> {
  const pool = candidates(name);
  const results = await pmap(pool, 8, async (c) => ({ ...(await checkDomain(c.domain)), kind: c.kind }));
  return results.filter((r) => r.status === "available").slice(0, limit);
}
