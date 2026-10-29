import { UA } from "./util";

export interface WebHit {
  title: string;
  url: string;
  snippet?: string;
}

export interface WebResult {
  /** "links" = no API key configured, only deep links are returned. */
  provider: "google-cse" | "brave" | "links";
  query: string;
  totalResults?: number;
  hits: WebHit[];
  links: { label: string; url: string }[];
  error?: string;
}

export function searchLinks(name: string) {
  const q = encodeURIComponent(`"${name}"`);
  return [
    { label: 'Google "name"', url: `https://www.google.com/search?q=${q}` },
    { label: "Google + app", url: `https://www.google.com/search?q=${q}+app` },
    { label: "Google Images", url: `https://www.google.com/search?tbm=isch&q=${q}` },
    { label: 'Bing "name"', url: `https://www.bing.com/search?q=${q}` },
    { label: 'DuckDuckGo "name"', url: `https://duckduckgo.com/?q=${q}` },
  ];
}

/**
 * Exact-phrase web search. Google offers no free scraping-safe endpoint, so this uses
 * the Programmable Search JSON API (GOOGLE_CSE_KEY + GOOGLE_CSE_CX) or Brave Search
 * (BRAVE_API_KEY) when configured, and otherwise falls back to deep links.
 */
export async function checkWeb(name: string): Promise<WebResult> {
  const query = `"${name}"`;
  const links = searchLinks(name);
  const { GOOGLE_CSE_KEY, GOOGLE_CSE_CX, BRAVE_API_KEY } = process.env;
  try {
    if (GOOGLE_CSE_KEY && GOOGLE_CSE_CX) {
      const url = `https://www.googleapis.com/customsearch/v1?key=${GOOGLE_CSE_KEY}&cx=${GOOGLE_CSE_CX}&q=${encodeURIComponent(query)}&num=5`;
      const res = await fetch(url, { signal: AbortSignal.timeout(8000), cache: "no-store" });
      if (!res.ok) throw new Error(`Google CSE HTTP ${res.status}`);
      const j: any = await res.json();
      return {
        provider: "google-cse",
        query,
        totalResults: Number(j.searchInformation?.totalResults ?? 0),
        hits: (j.items ?? []).map((i: any) => ({ title: i.title, url: i.link, snippet: i.snippet })),
        links,
      };
    }
    if (BRAVE_API_KEY) {
      const res = await fetch(`https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=5`, {
        headers: { "X-Subscription-Token": BRAVE_API_KEY, accept: "application/json", "user-agent": UA },
        signal: AbortSignal.timeout(8000),
        cache: "no-store",
      });
      if (!res.ok) throw new Error(`Brave HTTP ${res.status}`);
      const j: any = await res.json();
      const hits = (j.web?.results ?? []).map((r: any) => ({ title: r.title, url: r.url, snippet: r.description }));
      return { provider: "brave", query, hits, links };
    }
  } catch (e: any) {
    return { provider: "links", query, hits: [], links, error: e.message };
  }
  return { provider: "links", query, hits: [], links };
}
