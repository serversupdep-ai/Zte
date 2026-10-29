import { toLabel, UA } from "./util";

export interface RepoHit {
  fullName: string;
  stars: number;
  url: string;
  description?: string;
}

export interface GithubResult {
  name: string;
  /** The user / org / repo name that was looked up. */
  slug: string;
  handle: { status: "available" | "taken" | "unknown"; type?: string; url?: string };
  repos: { totalCount: number; exact: RepoHit[]; top: RepoHit[] };
  /** exact = a repo with this exact name has 100+ stars; similar = an exact-name repo exists; none = no exact-name repo */
  verdict: "none" | "similar" | "exact" | "error";
  /** Unauthenticated calls are limited (10 searches/min). Set GITHUB_TOKEN for batches. */
  authenticated: boolean;
  error?: string;
}

function headers(): Record<string, string> {
  const h: Record<string, string> = {
    accept: "application/vnd.github+json",
    "x-github-api-version": "2022-11-28",
    "user-agent": UA,
  };
  if (process.env.GITHUB_TOKEN) h.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

function rateLimited(res: Response) {
  return (res.status === 403 || res.status === 429) && res.headers.get("x-ratelimit-remaining") === "0";
}

export async function checkGithub(name: string): Promise<GithubResult> {
  const slug = toLabel(name);
  const authenticated = Boolean(process.env.GITHUB_TOKEN);
  const empty: GithubResult = {
    name,
    slug,
    handle: { status: "unknown" },
    repos: { totalCount: 0, exact: [], top: [] },
    verdict: "error",
    authenticated,
  };
  if (!slug) return { ...empty, error: "name has no usable characters" };

  try {
    const [userRes, searchRes] = await Promise.all([
      fetch(`https://api.github.com/users/${slug}`, { headers: headers(), signal: AbortSignal.timeout(8000), cache: "no-store" }),
      fetch(`https://api.github.com/search/repositories?q=${encodeURIComponent(slug)}+in:name&sort=stars&order=desc&per_page=30`, {
        headers: headers(),
        signal: AbortSignal.timeout(8000),
        cache: "no-store",
      }),
    ]);

    if (rateLimited(userRes) || rateLimited(searchRes)) {
      return { ...empty, error: "GitHub rate limit reached. Set GITHUB_TOKEN to raise it." };
    }

    let handle: GithubResult["handle"] = { status: "unknown" };
    if (userRes.status === 404) handle = { status: "available" };
    else if (userRes.ok) {
      const u: any = await userRes.json();
      handle = { status: "taken", type: u.type, url: u.html_url };
    }

    if (!searchRes.ok) return { ...empty, handle, error: `GitHub search HTTP ${searchRes.status}` };
    const j: any = await searchRes.json();
    const hit = (r: any): RepoHit => ({
      fullName: r.full_name,
      stars: r.stargazers_count,
      url: r.html_url,
      description: r.description ?? undefined,
    });
    const items: any[] = j.items ?? [];
    const exact = items.filter((r) => r.name.toLowerCase() === slug).map(hit);
    const verdict = exact.some((r) => r.stars >= 100) ? "exact" : exact.length ? "similar" : "none";

    return {
      name,
      slug,
      handle,
      repos: { totalCount: j.total_count ?? 0, exact: exact.slice(0, 5), top: items.slice(0, 5).map(hit) },
      verdict,
      authenticated,
    };
  } catch (e: any) {
    return { ...empty, error: e.message };
  }
}
