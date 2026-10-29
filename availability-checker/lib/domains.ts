import { pmap, toLabel, UA } from "./util";

export type DomainStatus = "available" | "taken" | "unknown";

export interface DomainResult {
  domain: string;
  tld: string;
  status: DomainStatus;
  /** rdap = authoritative registry answer, dns = heuristic (no NS records => probably free) */
  method: "rdap" | "dns" | "none";
  registrar?: string;
  expires?: string;
  registerUrl?: string;
}

export const DEFAULT_TLDS = ["com", "de", "app", "io", "co", "dev", "ai", "net", "org", "eu"];

// Registries that don't appear in rdap.org's bootstrap but run their own RDAP.
const RDAP_OVERRIDES: Record<string, string> = {
  de: "https://rdap.denic.de/domain/",
};

const timeout = () => AbortSignal.timeout(6000);

async function rdap(domain: string, tld: string): Promise<DomainResult | null> {
  const base = RDAP_OVERRIDES[tld] ?? "https://rdap.org/domain/";
  try {
    const res = await fetch(base + domain, {
      headers: { accept: "application/rdap+json", "user-agent": UA },
      redirect: "follow",
      signal: timeout(),
      cache: "no-store",
    });
    // rdap.org answers 404 itself when the TLD has no RDAP server -> not authoritative.
    if (new URL(res.url).hostname === "rdap.org" && res.status === 404) return null;
    if (res.status === 404) return { domain, tld, status: "available", method: "rdap" };
    if (res.status === 200) {
      const j: any = await res.json().catch(() => ({}));
      const exp = j.events?.find((e: any) => e.eventAction === "expiration")?.eventDate;
      const registrar = j.entities
        ?.find((e: any) => e.roles?.includes("registrar"))
        ?.vcardArray?.[1]?.find((v: any[]) => v[0] === "fn")?.[3];
      return { domain, tld, status: "taken", method: "rdap", registrar, expires: exp?.slice(0, 10) };
    }
    return null;
  } catch {
    return null;
  }
}

async function dns(domain: string, tld: string): Promise<DomainResult> {
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=NS`, {
      headers: { accept: "application/dns-json" },
      signal: timeout(),
      cache: "no-store",
    });
    const j: any = await res.json();
    if (j.Status === 3) return { domain, tld, status: "available", method: "dns" };
    if (j.Status === 0 && j.Answer?.length) return { domain, tld, status: "taken", method: "dns" };
    // NOERROR without NS: registered-but-parked, or a delegation-less name. Treat as taken.
    if (j.Status === 0) return { domain, tld, status: "taken", method: "dns" };
    return { domain, tld, status: "unknown", method: "dns" };
  } catch {
    return { domain, tld, status: "unknown", method: "none" };
  }
}

export async function checkDomain(domain: string): Promise<DomainResult> {
  const tld = domain.slice(domain.indexOf(".") + 1);
  const r = (await rdap(domain, tld)) ?? (await dns(domain, tld));
  if (r.status === "available") {
    r.registerUrl = `https://www.namecheap.com/domains/registration/results/?domain=${domain}`;
  }
  return r;
}

export async function checkDomains(name: string, tlds: string[] = DEFAULT_TLDS): Promise<DomainResult[]> {
  const label = toLabel(name);
  if (!label) return [];
  return pmap(tlds, 6, (tld) => checkDomain(`${label}.${tld}`));
}
