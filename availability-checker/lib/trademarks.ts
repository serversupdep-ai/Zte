export interface RegisterLink {
  id: "dpma" | "euipo" | "tmview" | "wipo";
  label: string;
  url: string;
  note: string;
}

export const NICE_CLASSES = [
  { n: 9, label: "Software / apps" },
  { n: 35, label: "Advertising / business" },
  { n: 42, label: "SaaS / IT services" },
];

/**
 * None of these registers offers a free, stable public search API, so this returns
 * deep links (pre-filled where the register supports it). A trademark search is a
 * manual review step: open each, filter to the Nice classes, and look at phonetic matches too.
 */
export function trademarkLinks(name: string): RegisterLink[] {
  const q = encodeURIComponent(name);
  return [
    {
      id: "dpma",
      label: "DPMAregister (DE)",
      url: "https://register.dpma.de/DPMAregister/marke/einsteiger",
      note: `Cannot be pre-filled. Search "${name}", Nice classes 9, 35, 42.`,
    },
    {
      id: "euipo",
      label: "EUIPO eSearch (EU)",
      url: `https://euipo.europa.eu/eSearch/#basic/1+1+1+1/50+50+50+50/${q}`,
      note: "EU trade marks. Filter to classes 9, 35, 42.",
    },
    {
      id: "tmview",
      label: "TMview (EU + national)",
      url: `https://www.tmdn.org/tmview/#/tmview/results?page=1&pageSize=30&criteria=F&basicSearch=${q}`,
      note: "Covers DE, EU and many national offices in one search.",
    },
    {
      id: "wipo",
      label: "WIPO Global Brand DB",
      url: `https://branddb.wipo.int/en/quicksearch?by=brandName&v=${q}&rows=30`,
      note: "International (Madrid) registrations.",
    },
  ];
}
