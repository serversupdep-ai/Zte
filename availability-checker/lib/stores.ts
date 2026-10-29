import { norm, UA } from "./util";

export interface StoreHit {
  title: string;
  developer: string;
  url: string;
  icon?: string;
}

export interface StoreResult {
  store: "app-store" | "google-play";
  /** exact = a listing is named like the query; similar = name appears inside other listings */
  verdict: "exact" | "similar" | "none" | "error";
  country: string;
  hits: StoreHit[];
  error?: string;
}

function judge(name: string, titles: string[]): "exact" | "similar" | "none" {
  const n = norm(name);
  if (!n) return "none";
  // "Name: Tagline" or "Name - Tagline" counts as the same name.
  const head = (t: string) => norm(t.split(/\s[-–—|]\s|:\s/)[0]);
  if (titles.some((t) => head(t) === n)) return "exact";
  if (titles.some((t) => norm(t).includes(n))) return "similar";
  return "none";
}

export async function checkAppStore(name: string, country = "de"): Promise<StoreResult> {
  try {
    const url = `https://itunes.apple.com/search?term=${encodeURIComponent(name)}&entity=software&country=${country}&limit=10`;
    const res = await fetch(url, { headers: { "user-agent": UA }, signal: AbortSignal.timeout(8000), cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const j: any = await res.json();
    const hits: StoreHit[] = (j.results ?? []).slice(0, 6).map((r: any) => ({
      title: r.trackName,
      developer: r.artistName,
      url: r.trackViewUrl,
      icon: r.artworkUrl60,
    }));
    return { store: "app-store", verdict: judge(name, hits.map((h) => h.title)), country, hits };
  } catch (e: any) {
    return { store: "app-store", verdict: "error", country, hits: [], error: e.message };
  }
}

export async function checkPlayStore(name: string, country = "de"): Promise<StoreResult> {
  try {
    const gplay: any = await import("google-play-scraper");
    const g = gplay.default ?? gplay;
    const list: any[] = await g.search({ term: name, num: 10, country, lang: "en", throttle: 0 });
    const hits: StoreHit[] = list.slice(0, 6).map((r) => ({
      title: r.title,
      developer: r.developer,
      url: r.url,
      icon: r.icon,
    }));
    return { store: "google-play", verdict: judge(name, hits.map((h) => h.title)), country, hits };
  } catch (e: any) {
    return { store: "google-play", verdict: "error", country, hits: [], error: e.message };
  }
}
