import type { FullCheck } from "./check";

export interface NameSummary {
  name: string;
  /** 0-100 screening heuristic: domain availability (50) + store clearance (50). Not legal advice. */
  score: number;
  verdict: "promising" | "mixed" | "crowded";
  domainsFree: string[];
  domainsTaken: string[];
  domainsUnknown: string[];
  ios: string;
  android: string;
  notes: string[];
  /** Only when GitHub was checked. Not part of the score. */
  github?: { handle: string; repos: string };
}

const STORE_POINTS: Record<string, number> = { none: 25, similar: 12, exact: 0, error: 0 };

export function summarize(c: FullCheck): NameSummary {
  const by = (s: string) => c.domains.filter((d) => d.status === s).map((d) => d.domain);
  const free = by("available");
  const taken = by("taken");
  const unknown = by("unknown");
  const isFree = (tld: string) => c.domains.some((d) => d.tld === tld && d.status === "available");

  const others = c.domains.filter((d) => d.tld !== "com" && d.tld !== "de");
  const otherShare = others.length ? others.filter((d) => d.status === "available").length / others.length : 0;
  const domainPts = (isFree("com") ? 22 : 0) + (isFree("de") ? 18 : 0) + Math.round(otherShare * 10);

  const [apple, play] = c.stores;
  const score = Math.min(100, domainPts + (STORE_POINTS[apple.verdict] ?? 0) + (STORE_POINTS[play.verdict] ?? 0));

  const notes: string[] = [];
  if (!isFree("com")) notes.push(".com is taken");
  if (!isFree("de")) notes.push(".de is taken");
  if (apple.verdict === "exact") notes.push("name already used on the App Store");
  if (play.verdict === "exact") notes.push("name already used on Google Play");
  if (apple.verdict === "error" || play.verdict === "error") notes.push("a store check failed, retry");
  if (unknown.length) notes.push(`${unknown.length} domain check(s) inconclusive`);
  if (c.domains.some((d) => d.status === "available" && d.method === "dns")) notes.push("some free TLDs are DNS-heuristic only");

  const gh = c.github;
  if (gh) {
    if (gh.handle.status === "taken") notes.push(`GitHub ${gh.handle.type === "Organization" ? "org" : "user"} @${gh.slug} is taken`);
    if (gh.verdict === "exact") notes.push(`popular GitHub repo with the same name (${gh.repos.exact[0].fullName}, ${gh.repos.exact[0].stars} stars)`);
    else if (gh.verdict === "similar") notes.push("a GitHub repo with the same name exists");
    else if (gh.verdict === "error") notes.push(`GitHub check failed: ${gh.error}`);
  }

  return {
    name: c.name,
    score,
    verdict: score >= 70 ? "promising" : score >= 40 ? "mixed" : "crowded",
    domainsFree: free,
    domainsTaken: taken,
    domainsUnknown: unknown,
    ios: apple.verdict,
    android: play.verdict,
    notes,
    ...(gh ? { github: { handle: gh.handle.status, repos: gh.verdict } } : {}),
  };
}
